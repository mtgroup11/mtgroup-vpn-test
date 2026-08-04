"""
MTGroup VPN Ultimate — Web3 Payment Verification Engine
═══════════════════════════════════════════════════════════════════
Automated asynchronous tracking of TON and TRX (TRC-20) public
ledgers to verify incoming payments and extend user subscriptions.
"""

import asyncio
import logging
from datetime import timedelta, timezone, datetime
from typing import Callable

import aiohttp
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.app.models import User, ProcessedTransaction
from backend.app.core.logging_config import audit_logger

logger = logging.getLogger("mtgroup.payments")

# Public RPC endpoints for demonstration
TON_API_URL = "https://toncenter.com/api/v2/getTransactions"
TRON_API_URL = "https://api.trongrid.io/v1/accounts/{}/transactions/trc20"
MIN_PAYMENT_USDT = 1.0  # Minimum expected payment threshold


class PaymentTrackerEngine:
    """
    Background worker that periodically polls Web3 APIs to verify
    payments sent to dedicated user wallets.
    """

    def __init__(self, db_session_factory: Callable[[], AsyncSession]):
        self._db_session_factory = db_session_factory
        self._is_running = False
        self._worker_task: asyncio.Task | None = None

    async def _is_tx_processed(self, db: AsyncSession, tx_hash: str) -> bool:
        stmt = select(ProcessedTransaction).where(ProcessedTransaction.tx_hash == tx_hash)
        result = await db.execute(stmt)
        return result.scalar_one_or_none() is not None

    async def start(self):
        if self._is_running:
            return
        self._is_running = True
        self._worker_task = asyncio.create_task(self._tracker_loop())
        logger.info("Payment Tracker Engine background worker started.")

    async def stop(self):
        self._is_running = False
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        logger.info("Payment Tracker Engine background worker stopped.")

    async def _tracker_loop(self):
        """Main polling loop running every 2 minutes."""
        async with aiohttp.ClientSession() as session:
            while self._is_running:
                try:
                    await self._process_payments(session)
                    await asyncio.sleep(120.0)
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Unexpected error in payment loop: {e}")
                    await asyncio.sleep(30.0)

    async def _process_payments(self, session: aiohttp.ClientSession):
        """Scans the DB for active crypto wallets and checks them against the blockchain."""
        try:
            async with self._db_session_factory() as db:
                # Get all users with crypto addresses
                stmt = select(User).where(
                    (User.crypto_address_ton.isnot(None)) | 
                    (User.crypto_address_trx.isnot(None))
                )
                users = (await db.execute(stmt)).scalars().all()

                for user in users:
                    if user.crypto_address_ton:
                        await self._check_ton_address(session, db, user)
                    
                    if user.crypto_address_trx:
                        await self._check_trx_address(session, db, user)

        except Exception as e:
            logger.error(f"Error accessing DB in payment processor: {e}")

    async def _check_ton_address(self, session: aiohttp.ClientSession, db: AsyncSession, user: User):
        """Fetch transactions for a TON address and verify deposits."""
        try:
            params = {"address": user.crypto_address_ton, "limit": 10}
            async with session.get(TON_API_URL, params=params, timeout=10) as response:
                if response.status != 200:
                    return
                data = await response.json()

                if not data.get("ok"):
                    return

                transactions = data.get("result", [])
                for tx in transactions:
                    tx_hash = tx.get("transaction_id", {}).get("hash")
                    
                    # Prevent replay attacks by checking DB
                    if not tx_hash or await self._is_tx_processed(db, tx_hash):
                        continue
                        
                    # Validate deposit (in a real app, verify amount and destination)
                    in_msg = tx.get("in_msg", {})
                    value_ton = int(in_msg.get("value", 0)) / 1e9
                    
                    if value_ton >= MIN_PAYMENT_USDT:
                        await self._extend_user_subscription(db, user, "TON", value_ton, tx_hash)
                    elif value_ton > 0:
                        logger.warning(f"Ignored TON deposit {value_ton} from {tx_hash}: Below minimum {MIN_PAYMENT_USDT}")

        except Exception as e:
            logger.warning(f"Failed to check TON address for user {user.username}: {e}")

    async def _check_trx_address(self, session: aiohttp.ClientSession, db: AsyncSession, user: User):
        """Fetch TRC-20 (USDT) transactions for a Tron address."""
        try:
            url = TRON_API_URL.format(user.crypto_address_trx)
            async with session.get(url, timeout=10) as response:
                if response.status != 200:
                    return
                data = await response.json()
                
                transactions = data.get("data", [])
                for tx in transactions:
                    tx_id = tx.get("transaction_id")
                    
                    if not tx_id or await self._is_tx_processed(db, tx_id):
                        continue
                        
                    # Check if it is an incoming transfer of USDT
                    if tx.get("to") == user.crypto_address_trx:
                        value_usdt = int(tx.get("value", 0)) / 1e6
                        
                        if value_usdt >= MIN_PAYMENT_USDT:
                            await self._extend_user_subscription(db, user, "TRX/USDT", value_usdt, tx_id)
                        elif value_usdt > 0:
                            logger.warning(f"Ignored TRX/USDT deposit {value_usdt} from {tx_id}: Below minimum {MIN_PAYMENT_USDT}")

        except Exception as e:
            logger.warning(f"Failed to check TRX address for user {user.username}: {e}")

    async def _extend_user_subscription(self, db: AsyncSession, user: User, network: str, amount: float, tx_hash: str):
        """Atomic operation to extend the user's expiration and bandwidth limit."""
        try:
            # Refresh user
            await db.refresh(user)
            
            # Policy: 1 USDT = 30 days and 50GB
            # For demonstration, we simply add 30 days and 50GB per valid payment
            now_utc = datetime.now(timezone.utc)
            
            if not user.expire_date or user.expire_date < now_utc:
                user.expire_date = now_utc + timedelta(days=30)
            else:
                user.expire_date = user.expire_date + timedelta(days=30)
                
            user.data_limit_bytes += (50 * 1024 * 1024 * 1024)
            user.is_active = True
            
            # Persist processed transaction to prevent double credits on restart
            pt = ProcessedTransaction(tx_hash=tx_hash, network=network, amount=amount)
            db.add(pt)
            
            await db.commit()
            
            audit_logger.log_user_event(user.username, "payment_received", f"{network} payment verified. TxHash: {tx_hash}. Account extended.")
            logger.info(f"Subscription extended for {user.username} via {network} payment.")
            
        except Exception as e:
            await db.rollback()
            logger.error(f"Failed to extend subscription for {user.username}: {e}")
