from motor.motor_asyncio import AsyncIOMotorClient


class MongoDB:
    def __init__(self):
        self.client = None

    def connect(self):
        self.client = AsyncIOMotorClient("localhost:27017")

    def close(self):
        self.client.close()


mongodb = MongoDB()
