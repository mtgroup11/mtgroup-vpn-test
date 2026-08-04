import asyncio
from backend.app.core.config import settings
from backend.app.models import create_db_engine, init_db, User, create_session_factory
from sqlalchemy import select

async def main():
    print("URL:", settings.DATABASE_URL)
    engine = create_db_engine(settings.DATABASE_URL)
    print("Initializing DB...")
    await init_db(engine)
    print("DB Initialized.")
    
    async_session_factory = create_session_factory(engine)
    async with async_session_factory() as session:
        print("Selecting User...")
        try:
            result = await session.execute(select(User))
            users = result.scalars().all()
            print("Users:", users)
        except Exception as e:
            print("ERROR:", type(e), str(e))
    await engine.dispose()

if __name__ == "__main__":
    asyncio.run(main())
