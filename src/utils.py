from bson import ObjectId


def convert_list_objectid_to_str(datas):
    for data in datas:
        data["_id"] = str(data["_id"])
    return datas
