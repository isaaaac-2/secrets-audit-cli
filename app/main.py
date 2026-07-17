from fastapi import FastAPI

app = FastAPI()


@app.get("/")
def root():
    return {"message": "Security Scanner API"}


@app.get("/health")
def health():
    return {"status": "healthy"}
