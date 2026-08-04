import asyncio
import httpx

async def run_test():
    async with httpx.AsyncClient(base_url="http://127.0.0.1:8443") as client:
        # 1. Login
        print("Logging in...")
        r = await client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
        if r.status_code != 200:
            print("Login failed:", r.status_code, r.text)
            return
        token = r.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # 2. Stats
        print("Fetching stats...")
        r = await client.get("/api/system/stats", headers=headers)
        print("Stats:", r.status_code, r.text[:100])
        
        # 3. Users
        print("Fetching users...")
        r = await client.get("/api/users?per_page=50", headers=headers)
        print("Users:", r.status_code, r.text[:100])
        
        # 4. Nodes
        print("Fetching nodes...")
        r = await client.get("/api/nodes", headers=headers)
        print("Nodes:", r.status_code, r.text[:100])
        
        # 5. Config
        print("Fetching config...")
        r = await client.get("/api/system/config", headers=headers)
        print("Config:", r.status_code, r.text[:100])

if __name__ == "__main__":
    asyncio.run(run_test())
