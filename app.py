# python 3.9
import base64
import html
import json
import os
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sentence_transformers import SentenceTransformer
from tensorflow.keras.models import load_model
from huggingface_hub import hf_hub_download
import uvicorn
import boto3
from botocore.exceptions import BotoCoreError, ClientError
import asyncio
import logging
from wslogger import logger

log = logging.getLogger(__name__)

class Payload(BaseModel):
    payload: str
    event_info: str
    request_created_at: str

load_dotenv()

AWS_REGION = os.getenv("AWS_REGION")
AWS_API_KEY_NAME = os.getenv("AWS_API_KEY_NAME")
AWS_API_SECRET_KEY_NAME = os.getenv("AWS_API_SECRET_KEY_NAME")

app = FastAPI()

def get_secret():

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=AWS_REGION
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=AWS_API_KEY_NAME
        )
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise e

    secret = get_secret_value_response['SecretString']
    secret_data = json.loads(secret)
    api_key = secret_data.get(AWS_API_SECRET_KEY_NAME)

    return api_key
    
def load_encoder():
    model_name_or_path = os.environ.get("model_name_or_path", "sentence-transformers/all-MiniLM-L6-v2")
    return SentenceTransformer(model_name_or_path)

encoder = load_encoder()

def load_model_detector():
    local_model_path = hf_hub_download(
        repo_id="noobpk/web-attack-detection",
        filename="model.h5"
    )
    return load_model(local_model_path)
    
model_detector = load_model_detector()

def ws_decoder(_string: str) -> str:
    string = _string.replace(r"\%", "%").replace(r"\\", "").replace(r"<br/>", "")
    string = string.encode().decode("unicode_escape")
    string = urllib.parse.unquote(string)
    string = html.unescape(string)
    base64_pattern = r"( |,|;)base64,([A-Za-z0-9+/]*={0,2})"
    match = re.search(base64_pattern, string)
    if match:
        encoded_string = match.group(2)
        try:
            decoded_string = base64.b64decode(encoded_string).decode()
            string = string.replace(encoded_string, decoded_string)
        except:
            pass
    return string

def get_decoded_auth(authorization: str) -> str:
    try:
        if not authorization.startswith("Basic "):
            raise HTTPException(status_code=401, detail={"status": "error", "message": "Unauthorized", "error_code": 401})
        encoded_auth = authorization[len("Basic "):]
        decoded_auth = base64.b64decode(encoded_auth).decode()
        return decoded_auth
    except Exception:
        raise HTTPException(status_code=401, detail={"status": "error", "message": "Unauthorized", "error_code": 401})

def extract_eventInfo(event_info: str):
    try:
        agent_id, service_name, event_id = event_info.split("|")
        return {
            "agent_id": agent_id,
            "service_name": service_name,
            "event_id": event_id,
        }
    except ValueError:
        log.error(f"Invalid event_info format: {event_info}. Expected format: agent_id|service_name|event_id")

async def process_loggcollection(payload: Payload, eventInfo: str, score: float):
    info = extract_eventInfo(payload.event_info)
    # Construct log entry
    logEntry = {
        "name": "ws-web-attack-detection",
        "agent_id": info["agent_id"],
        "source": str(info["service_name"]).lower(),
        "destination": "ws-web-attack-detection",
        "event_info": eventInfo,
        "level": "INFO",
        "event_id": info["event_id"],
        "type": "SERVICE_EVENT",
        "raw_request": payload.payload,
        "prediction": score,
        "message": "Received request from service",
        "request_created_at": payload.request_created_at,
        "request_processed_at": datetime.now().astimezone().isoformat(),
        "timestamp": datetime.now().astimezone().isoformat()
    }
    logEntryJSON = json.dumps(logEntry, ensure_ascii=False).replace('"', '\\"')
    logger.info(logEntryJSON)
        
@app.get("/api/v1/ws/services/web-attack-detection/ping")
def ping_info(authorization: str = Header(None)):
    decoded_auth = get_decoded_auth(authorization)
    apiKey = get_secret()
    expectedAuthValue = f"ws:{apiKey}"
    if decoded_auth != expectedAuthValue:
        raise HTTPException(status_code=401, detail={"status": "error", "message": "Unauthorized", "error_code": 401})
    return {
        "model": "noobpk/web-attack-detection",
        "sample": "592479",
        "max_input_length": "unlimit",
        "vector_size": "384",
        "param": "2536417",
        "model_build_at": "11-11-2023",
        "encoder": "sentence-transformers/all-MiniLM-L6-v2",
        "author": "noobpk - lethanhphuc",
    }

@app.post("/api/v1/ws/services/web-attack-detection")
async def detection(payload: Payload, authorization: str = Header(None)):
    try:
        # Enforce a 30-second timeout for the entire function
        result = await asyncio.wait_for(process_detection(payload, authorization), timeout=30.0)
        return result
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail={"status": "error", "message": "Request timed out", "error_code": 504})
    
async def process_detection(payload: Payload, authorization: str):
    decoded_auth = get_decoded_auth(authorization)
    apiKey = get_secret()
    expectedAuthValue = f"ws:{apiKey}"
    if decoded_auth != expectedAuthValue:
        raise HTTPException(status_code=401, detail={"status": "error", "message": "Unauthorized", "error_code": 401})
    
    payload_data = payload.payload
    decode_payload = ws_decoder(payload_data)
    embeddings = encoder.encode(decode_payload).reshape((1, 384))
    
    def predict():
        return model_detector.predict(embeddings)

    def calculate_accuracy(prediction):
        return float(prediction[0][0] * 100)

    with ThreadPoolExecutor() as executor:
        prediction = executor.submit(predict).result()
        accuracy = executor.submit(calculate_accuracy, prediction).result()

   # Replace "WS_GATEWAY_SERVICE" with "WS_WEB_ATTACK_DETECTION" in event_info
    event_info = payload.event_info.replace("WS_GATEWAY_SERVICE", "WS_WEB_ATTACK_DETECTION")

    # Trigger log collection (do not await to keep async non-blocking)
    asyncio.create_task(process_loggcollection(payload, eventInfo=event_info, score=accuracy))

    return JSONResponse(content={
        "status": "success",
        "message": "Request processed successfully",
        "data": {
            "threat_metrix": {
                "origin_payload": payload_data,
                "decode_payload": decode_payload,
                "score": accuracy,
            }
        },
        "event_info": event_info,
        "request_created_at": payload.request_created_at,
        "request_processed_at": datetime.now().astimezone().isoformat()
    })

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5001)