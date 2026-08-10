"""
MTGroup VPN Ultimate — AmneziaWG Peer Provisioning Tests

The properties that matter here:
  • the keypair is real (public key derived from private, not independent
    random bytes — the previous implementation got this wrong)
  • fetching a config twice returns the SAME peer, because a new keypair
    would invalidate the config the user already installed
  • two peers on one node can never share a tunnel IP
"""

from __future__ import annotations

import base64

import pytest
import pytest_asyncio

from backend.app.core.wireguard_peers import (
    NoAddressesAvailable,
    candidate_addresses,
    generate_keypair,
    get_or_create_peer,
)
from backend.app.models import Node, NodeProtocol, Subscription, User, create_session_factory


class TestGenerateKeypair:
    def test_keys_are_32_raw_bytes_base64(self):
        private, public = generate_keypair()
        assert len(base64.b64decode(private)) == 32
        assert len(base64.b64decode(public)) == 32

    def test_public_key_is_derived_from_the_private_key(self):
        """
        The load-bearing property. An earlier implementation generated the
        two halves independently, producing keypairs that look valid and
        can never complete a handshake.
        """
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import x25519

        private, public = generate_keypair()
        loaded = x25519.X25519PrivateKey.from_private_bytes(base64.b64decode(private))
        expected = loaded.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        assert base64.b64decode(public) == expected

    def test_each_call_is_unique(self):
        assert generate_keypair()[0] != generate_keypair()[0]


class TestCandidateAddresses:
    def test_reserves_the_first_host_for_the_server(self):
        addrs = candidate_addresses("10.8.0.0/24")
        assert addrs[0] == "10.8.0.2"  # .1 is the server
        assert "10.8.0.1" not in addrs

    def test_excludes_network_and_broadcast(self):
        addrs = candidate_addresses("10.8.0.0/24")
        assert "10.8.0.0" not in addrs
        assert "10.8.0.255" not in addrs

    def test_respects_a_smaller_prefix(self):
        assert candidate_addresses("10.9.0.0/30") == ["10.9.0.2"]


@pytest_asyncio.fixture
async def wg_env(db_engine):
    factory = create_session_factory(db_engine)
    async with factory() as session:
        user = User(username="wg-user", hashed_password="x")
        session.add(user)
        await session.flush()

        sub = Subscription(user_id=user.id, token="wg-token")
        node = Node(
            name="wg-node",
            address="203.0.113.10",
            protocol=NodeProtocol.AMNEZIA_WG,
            amnezia_subnet="10.8.0.0/24",
            amnezia_server_public_key="SERVERPUBKEY=",
        )
        session.add_all([sub, node])
        await session.commit()
        await session.refresh(sub)
        await session.refresh(node)
        yield session, sub, node


class TestGetOrCreatePeer:
    @pytest.mark.asyncio
    async def test_creates_a_peer_with_the_first_free_address(self, wg_env):
        session, sub, node = wg_env
        peer, created = await get_or_create_peer(session, subscription_id=sub.id, node=node)
        assert created is True
        assert peer.assigned_ip == "10.8.0.2"
        assert peer.public_key and peer.private_key
        assert peer.is_synced_to_node is False

    @pytest.mark.asyncio
    async def test_is_idempotent_for_the_same_subscription(self, wg_env):
        """Refetching a config must not rotate the user's keys."""
        session, sub, node = wg_env
        first, created_first = await get_or_create_peer(session, subscription_id=sub.id, node=node)
        await session.commit()

        second, created_second = await get_or_create_peer(session, subscription_id=sub.id, node=node)
        assert created_first is True
        assert created_second is False
        assert second.id == first.id
        assert second.private_key == first.private_key
        assert second.assigned_ip == first.assigned_ip

    @pytest.mark.asyncio
    async def test_second_subscription_gets_a_different_address(self, wg_env):
        session, sub, node = wg_env
        user2 = User(username="wg-user-2", hashed_password="x")
        session.add(user2)
        await session.flush()
        sub2 = Subscription(user_id=user2.id, token="wg-token-2")
        session.add(sub2)
        await session.flush()

        first, _ = await get_or_create_peer(session, subscription_id=sub.id, node=node)
        second, _ = await get_or_create_peer(session, subscription_id=sub2.id, node=node)

        assert first.assigned_ip != second.assigned_ip
        assert {first.assigned_ip, second.assigned_ip} == {"10.8.0.2", "10.8.0.3"}

    @pytest.mark.asyncio
    async def test_raises_when_the_subnet_is_exhausted(self, wg_env):
        session, sub, node = wg_env
        node.amnezia_subnet = "10.9.0.0/30"  # exactly one usable peer address
        await session.flush()

        await get_or_create_peer(session, subscription_id=sub.id, node=node)

        user2 = User(username="wg-user-3", hashed_password="x")
        session.add(user2)
        await session.flush()
        sub2 = Subscription(user_id=user2.id, token="wg-token-3")
        session.add(sub2)
        await session.flush()

        with pytest.raises(NoAddressesAvailable):
            await get_or_create_peer(session, subscription_id=sub2.id, node=node)

    @pytest.mark.asyncio
    async def test_private_key_is_encrypted_at_rest(self, wg_env):
        """The column uses EncryptedType — the raw row must not hold the key."""
        from sqlalchemy import text

        session, sub, node = wg_env
        peer, _ = await get_or_create_peer(session, subscription_id=sub.id, node=node)
        await session.commit()
        plaintext = peer.private_key

        raw = (
            await session.execute(text("select private_key from wireguard_peers where id = :i"), {"i": peer.id})
        ).scalar_one()
        assert raw != plaintext, "private key was stored in plaintext"
        assert plaintext not in raw


class TestRevokePeers:
    @pytest.mark.asyncio
    async def test_tells_the_node_to_forget_the_peer(self, wg_env, monkeypatch):
        """
        Deleting the row is not revocation. The peer lives in the node's
        WireGuard config, so unless the node is told, the key the user
        already holds keeps working — deleting a user would *look* like it
        revoked access while their tunnel stayed up.
        """
        from backend.app.core.wireguard_peers import revoke_peers

        session, sub, node = wg_env
        peer, _ = await get_or_create_peer(session, subscription_id=sub.id, node=node)
        await session.commit()
        public_key = peer.public_key

        pushed = []

        async def _fake_sync(target_node, payload):
            pushed.append(payload)
            return True

        monkeypatch.setattr("backend.app.orchestrator.orchestrator.sync_node_config", _fake_sync)

        revoked = await revoke_peers(session, subscription_ids=[sub.id])
        await session.commit()

        assert revoked == 1
        assert pushed[0]["payload"]["action"] == "remove_peer"
        assert pushed[0]["payload"]["public_key"] == public_key

        from sqlalchemy import select as sa_select

        from backend.app.models import WireGuardPeer

        remaining = (
            await session.execute(sa_select(WireGuardPeer).where(WireGuardPeer.subscription_id == sub.id))
        ).scalars().all()
        assert remaining == []

    @pytest.mark.asyncio
    async def test_unreachable_node_does_not_block_revocation(self, wg_env, monkeypatch):
        """An offline node must not make deleting a user impossible."""
        from backend.app.core.wireguard_peers import revoke_peers

        session, sub, node = wg_env
        await get_or_create_peer(session, subscription_id=sub.id, node=node)
        await session.commit()

        async def _failing_sync(target_node, payload):
            return False

        monkeypatch.setattr("backend.app.orchestrator.orchestrator.sync_node_config", _failing_sync)

        revoked = await revoke_peers(session, subscription_ids=[sub.id])
        await session.commit()

        assert revoked == 0  # reported as not deregistered...
        from sqlalchemy import select as sa_select

        from backend.app.models import WireGuardPeer

        remaining = (
            await session.execute(sa_select(WireGuardPeer).where(WireGuardPeer.subscription_id == sub.id))
        ).scalars().all()
        assert remaining == []  # ...but the row is still cleaned up

    @pytest.mark.asyncio
    async def test_empty_input_is_a_noop(self, wg_env):
        from backend.app.core.wireguard_peers import revoke_peers

        session, _, _ = wg_env
        assert await revoke_peers(session, subscription_ids=[]) == 0


class TestAddressUniquenessIsEnforcedByTheDatabase:
    @pytest.mark.asyncio
    async def test_duplicate_ip_on_one_node_is_rejected(self, wg_env):
        """
        The allocator avoids collisions, but the constraint is what makes
        that guarantee hold under concurrency rather than by luck.
        """
        from sqlalchemy.exc import IntegrityError

        from backend.app.models import WireGuardPeer

        session, sub, node = wg_env
        peer, _ = await get_or_create_peer(session, subscription_id=sub.id, node=node)
        await session.commit()

        user2 = User(username="wg-clash", hashed_password="x")
        session.add(user2)
        await session.flush()
        sub2 = Subscription(user_id=user2.id, token="wg-clash-token")
        session.add(sub2)
        await session.flush()

        session.add(
            WireGuardPeer(
                subscription_id=sub2.id,
                node_id=node.id,
                private_key="k",
                public_key="p",
                assigned_ip=peer.assigned_ip,  # same IP, same node
            )
        )
        with pytest.raises(IntegrityError):
            await session.commit()
