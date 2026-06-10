#!/usr/bin/env python3
"""Start the policy generation system on port 8001."""

import uvicorn

from src.configs.index import API_HOST, API_PORT


if __name__ == "__main__":
    uvicorn.run("src.main:app", host=API_HOST, port=API_PORT, reload=False)

