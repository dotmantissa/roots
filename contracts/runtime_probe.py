# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *
class RuntimeProbe(gl.Contract):
    owner: Address
    count: u32
    entries: TreeMap[str, str]
    history: DynArray[str]
    def __init__(self):
        self.owner = gl.message.sender_address
        self.count = u32(0)
    @gl.public.view
    def identity(self) -> dict:
        return {"runner": "1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6", "owner": str(self.owner)}
