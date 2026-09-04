import os
import re
import json
import hashlib
import time
import glob
import yaml
from kafka import KafkaConsumer, KafkaProducer  # type: ignore[import-not-found]
from minio import Minio  # type: ignore[import-not-found]
from io import BytesIO

KAFKA_BROKER = os.getenv("KAFKA_BROKER", "localhost:9092")
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "localhost:9000")
MINIO_USER = os.getenv("MINIO_USER", "minioadmin")
MINIO_PASS = os.getenv("MINIO_PASS", "minioadmin")

minio_client = Minio(
    MINIO_ENDPOINT,
    access_key=MINIO_USER,
    secret_key=MINIO_PASS,
    secure=False
)
RAW_BUCKET = "raw-logs-store"

def init_minio():
    for _ in range(10):
        try:
            if not minio_client.bucket_exists(RAW_BUCKET):
                minio_client.make_bucket(RAW_BUCKET)
            break
        except Exception:
            time.sleep(2)

def load_rules():
    rules = []
    for filepath in glob.glob("/app/rules/*.yaml"):
        with open(filepath, 'r') as f:
            data = yaml.safe_load(f)
            if data and 'pattern' in data:
                data['compiled_regex'] = re.compile(data['pattern'])
                rules.append(data)
    return rules

def compute_hash(data_bytes, prev_hash="00000000000000000000000000000000"):
    hasher = hashlib.sha256()
    hasher.update(prev_hash.encode('utf-8'))
    hasher.update(data_bytes)
    return hasher.hexdigest()

def main():
    init_minio()
    rules = load_rules()
    
    consumer = None
    for _ in range(15):
        try:
            consumer = KafkaConsumer(
                'raw-logs',
                bootstrap_servers=[KAFKA_BROKER],
                auto_offset_reset='earliest',
                value_deserializer=lambda m: m
            )
            producer = KafkaProducer(
                bootstrap_servers=[KAFKA_BROKER],
                value_serializer=lambda v: json.dumps(v).encode('utf-8')
            )
            break
        except Exception:
            time.sleep(2)

    if not consumer:
        return

    last_hash = "00000000000000000000000000000000"

    for msg in consumer:
        raw_bytes = msg.value
        raw_str = raw_bytes.decode('utf-8', errors='ignore')

        # 1. Preserve Raw & Hash-chain ID link
        current_hash = compute_hash(raw_bytes, last_hash)
        last_hash = current_hash
        
        object_name = f"{current_hash}.log"
        minio_client.put_object(
            RAW_BUCKET,
            object_name,
            BytesIO(raw_bytes),
            length=len(raw_bytes),
            content_type="text/plain"
        )

        # 2. Parse Log via Config Rule
        extracted_fields = {}
        matched_rule = None
        for rule in rules:
            match = rule['compiled_regex'].search(raw_str)
            if match:
                extracted_fields = match.groupdict()
                matched_rule = rule
                break

        # Safely handle ocsf_mapping dictionary lookup
        ocsf_mapping = {}
        if matched_rule and matched_rule.get('ocsf_mapping'):
            ocsf_mapping = matched_rule['ocsf_mapping']
        
        # 3. Normalize into OCSF Standard Schema
        ocsf_event = {
            "class_uid": ocsf_mapping.get("class_uid", 0),
            "class_name": ocsf_mapping.get("class_name", "Unknown"),
            "category_uid": ocsf_mapping.get("category_uid", 0),
            "category_name": ocsf_mapping.get("category_name", "Unknown"),
            "activity_id": ocsf_mapping.get("activity_id", 0),
            "severity_id": ocsf_mapping.get("severity_id", 0),
            "time": extracted_fields.get("timestamp", str(time.time())),
            "src_endpoint": {
                "ip": extracted_fields.get("src_ip"),
                "port": int(extracted_fields["src_port"]) if extracted_fields.get("src_port") else None
            },
            "dst_endpoint": {
                "ip": extracted_fields.get("dst_ip"),
                "port": int(extracted_fields["dst_port"]) if extracted_fields.get("dst_port") else None
            },
            "action": extracted_fields.get("action"),
            "unmapped": {
                "hostname": extracted_fields.get("hostname"),
                "priority": extracted_fields.get("priority")
            },
            "uncompromised_raw_hash": current_hash
        }

        # 4. Output Stream
        producer.send('normalized-logs', ocsf_event)
        print(f"\n[PROCESSED LOG]")
        print(f"Raw Hash Link: {current_hash}")
        print(f"OCSF Output: {json.dumps(ocsf_event, indent=2)}")

if __name__ == "__main__":
    main()