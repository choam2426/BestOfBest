from src.db_connect import mongodb
from src.log_parser import main

mongodb.connect()
main()
