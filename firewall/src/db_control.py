from bson import ObjectId


async def update_number_when_delete(collection, number):
    cursor = await collection.find({"number": {"$gt": number}}).to_list(None)
    for document in cursor:
        document["number"] -= 1
        document["real_num"] -= 2
        await collection.update_one({"_id": document["_id"]}, {"$set": document})


async def update_pkt(collection, id):
    log_rule = await collection.find_one({"_id": ObjectId(id)})
    if log_rule:
        num = log_rule["pkt"] + 1
        await collection.update_one({"_id": ObjectId(id)}, {"$set": {"pkt": num}})
