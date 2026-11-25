"""
CloudGuard Pre-Storage DLP Gateway — FastAPI Application Entrypoint.
"""

import os
import sys
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Ensure root directory is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.config import settings
from backend.routes import auth, scan, events, policies, dashboard, security_demo
from database.connection import DatabaseManager
from database.seed import seed_database


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: connect to MongoDB Atlas (or fallback) and seed initial accounts/policies
    await DatabaseManager.connect(uri=settings.MONGODB_URI, db_name=settings.MONGODB_DB_NAME)
    await seed_database()
    yield
    # Shutdown cleanup if needed
    if DatabaseManager.client:
        DatabaseManager.client.close()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Pre-Storage Cloud Data Loss Prevention Gateway with S3 Dual-Bucket Routing",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Modular Routers
app.include_router(auth.router)
app.include_router(scan.router)
app.include_router(events.router)
app.include_router(policies.router)
app.include_router(dashboard.router)
app.include_router(security_demo.router)


@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "security_mode": settings.SECURITY_MODE,
        "database": "MongoDB Atlas" if DatabaseManager.is_live_atlas else "Local Persistent Store"
    }
