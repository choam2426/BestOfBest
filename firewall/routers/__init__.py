from .logs import router as logs_router
from .rules import router as rules_router

routers = [rules_router, logs_router]
