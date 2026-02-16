from pydantic import BaseModel

class SupervisorSchema(BaseModel):
    next_step: str
    message: str