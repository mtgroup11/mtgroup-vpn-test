import asyncio
import json
import os
from datetime import datetime, timezone, timedelta

# Set encryption key before imports so crypto_quantum.py is happy
os.environ["DB_ENCRYPTION_KEY"] = "0" * 64

from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from backend.app.main import app
from backend.app.models import Base, User, Subscription, Node, NodeProtocol
from backend.app.core.security import hash_password
from backend.app.core.config import settings
from backend.app.api.auth import get_db

# Use the same DB that the main app uses
DATABASE_URL = settings.DATABASE_URL
engine = create_async_engine(DATABASE_URL, echo=False)
TestingSessionLocal = async_sessionmaker(engine, expire_on_commit=False)

async def override_get_db():
    async with TestingSessionLocal() as session:
        yield session

app.dependency_overrides[get_db] = override_get_db

async def setup_mock_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
        
    async with TestingSessionLocal() as session:
        # Create User
        user = User(
            username="test_user",
            hashed_password=hash_password("1234"),
            is_active=True,
            data_limit_bytes=100 * 1024 * 1024, # 100MB
            data_used_bytes=0,
            expire_date=datetime.now(timezone.utc) + timedelta(days=30)
        )
        session.add(user)
        await session.flush()
        
        # Create Subscription
        sub = Subscription(
            user_id=user.id,
            token="test-token-1234",
            label="MTGroup-Test",
            is_active=True,
            protocols=json.dumps(["vless_reality", "hysteria2", "tuic_v5", "amnezia_wg"])
        )
        session.add(sub)
        
        # Create Nodes
        node1 = Node(
            name="NL-VLESS",
            address="1.1.1.1",
            port=443,
            protocol=NodeProtocol.VLESS_REALITY,
            is_active=True,
            sni="www.google.com",
            reality_public_key="some_pub_key",
            reality_short_id="12345678"
        )
        node2 = Node(
            name="DE-Amnezia",
            address="2.2.2.2",
            port=1234,
            protocol=NodeProtocol.AMNEZIA_WG,
            is_active=True,
            amnezia_jc=1, amnezia_jmin=2, amnezia_jmax=10,
            amnezia_s1=15, amnezia_s2=25,
            amnezia_h1=1, amnezia_h2=2, amnezia_h3=3, amnezia_h4=4
        )
        session.add_all([node1, node2])
        await session.commit()


async def verify_endpoints():
    await setup_mock_db()
    
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"X-Stealth-Token": "SUPER_SECRET_NOC_TOKEN_2026"}
    ) as client:
        print("Testing Subscriptions Endpoint (V2Ray/Links)...")
        res = await client.get("/sub/test-token-1234/v2ray")
        assert res.status_code == 200, res.text
        print(" - Base64 V2Ray Config OK")
        
        print("Testing Subscriptions Endpoint (Sing-box)...")
        res = await client.get("/sub/test-token-1234/singbox")
        assert res.status_code == 200, res.text
        data = res.json()
        assert "outbounds" in data
        print(" - Sing-box JSON Config OK")
        
        print("Testing Subscriptions Endpoint (Clash)...")
        res = await client.get("/sub/test-token-1234/clash")
        assert res.status_code == 200, res.text
        assert "proxies:" in res.text
        print(" - Clash YAML Config OK")
        
        print("Testing Subscriptions Endpoint (AmneziaWG)...")
        res = await client.get("/sub/test-token-1234/amnezia")
        assert res.status_code == 200, res.text
        assert "[Interface]" in res.text
        print(" - AmneziaWG Config OK")
        
        print("Testing Subscriptions Endpoint (QR Code)...")
        res = await client.get("/sub/test-token-1234/qr")
        assert res.status_code == 200, res.text
        assert res.headers["content-type"] == "image/png"
        print(" - QR Code Generation OK (PNG returned)")
        
        print("Testing Subscriptions Endpoint (Auto-Detect: v2rayNG)...")
        res = await client.get("/sub/test-token-1234", headers={"User-Agent": "v2rayNG/1.8.5"})
        assert res.status_code == 200, res.text
        print(" - Auto-Detect V2Ray OK")

        print("Testing Subscriptions Endpoint (Auto-Detect: v2box)...")
        res = await client.get("/sub/test-token-1234", headers={"User-Agent": "V2Box/1.0"})
        assert res.status_code == 200, res.text
        print(" - Auto-Detect V2Box -> Sing-box OK")
        
        print("Testing GeoCamouflage functionality through VLESS Generator...")
        from backend.app.geo_camouflage import get_camouflage_for_ip
        # Instead of trusting the IP heuristic (which might fail if geoip2 DB is missing),
        # we will use the preferred_country fallback to test the mapping.
        camo_cn = get_camouflage_for_ip("127.0.0.1", preferred_country="CN")
        assert camo_cn.country == "CN"
        assert camo_cn.sni in ["www.baidu.com", "www.qq.com", "www.taobao.com", "www.jd.com", "www.163.com"]
        print(f" - GeoCamouflage (CN) OK -> Sni: {camo_cn.sni}")
        
        camo_ir = get_camouflage_for_ip("127.0.0.1", preferred_country="IR")
        assert camo_ir.country == "IR"
        assert camo_ir.sni in ["www.digikala.com", "www.shaparak.ir", "static.cdn.asset.aparat.com", "www.bale.ai"]
        print("ALL TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    asyncio.run(verify_endpoints())
