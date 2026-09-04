from fastapi import FastAPI
from pydantic import BaseModel

from sentence_transformers import SentenceTransformer

model = SentenceTransformer(
    "BAAI/bge-m3"
)

app = FastAPI()


class Request(BaseModel):

    text: str


@app.post("/embed")

def embed(req: Request):

    vector = model.encode(
        req.text
    ).tolist()

    return {

        "embedding": vector

    }
