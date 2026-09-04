from kafka import KafkaProducer
import time

producer = KafkaProducer(
    bootstrap_servers=['localhost:9092'],
    value_serializer=lambda v: v.encode('utf-8')
)

test_logs = [
    '<134>Nov 15 10:23:45 fw01 ALLOW SRC=192.168.1.50 DST=8.8.8.8 SPT=52341 DPT=443',
    '<134>Nov 15 10:24:12 fw01 DENY SRC=203.0.113.100 DST=8.8.4.4 SPT=54321 DPT=443',
]

for log in test_logs:
    producer.send('raw-logs', log)
    print(f"Sent: {log}")
    time.sleep(1)

producer.close()
print("Done")