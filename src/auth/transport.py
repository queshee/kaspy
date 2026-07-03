from typing import Type, Optional

import aiohttp
from pydantic import BaseModel

class Transport:
    def __init__(
        self, 
        session: aiohttp.ClientSession,
        base_url: str = "https://entrance-pay.kaspi.kz"
    ) -> None:
        self.session = session
        self.base_url = base_url
    
    async def get(self, endpoint: str, headers: Type[BaseModel], params: Optional[Type[BaseModel]] = None) -> dict:
        async with self.session.get(
            f"{self.base_url}/{endpoint}", 
            headers=headers.model_dump(by_alias=True, mode="json"), 
            params=params.model_dump(by_alias=True, mode="json") if params else None
        ) as response:
            return await response.json()

    async def post(self, endpoint: str, headers: Type[BaseModel], payload: Type[BaseModel]) -> dict:
        async with self.session.post(
            f"{self.base_url}/{endpoint}", 
            headers=headers.model_dump(by_alias=True, mode="json"), 
            json=payload.model_dump(by_alias=True, mode="json")
        ) as response:
            return await response.json()
    