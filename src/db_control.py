async def update_number_when_delete(collection, number):
    cursor = await collection.find({"number": {"$gt": number}}).to_list(None)
    for document in cursor:
        document["number"] -= 1
        document["real_num"] -= 2
        await collection.update_one({"_id": document["_id"]}, {"$set": document})
