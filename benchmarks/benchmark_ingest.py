import csv 
import time
import tracemalloc
from pathlib import Path


from loglens.ingest import ingest_file

BENCHMARK_FILE = Path("benchmarks/sample_100k.csv")
EVENT_COUNT = 100_000

def create_sample_file():
    BENCHMARK_FILE.parent.mkdir(parents=True, exist_ok=True)


    with BENCHMARK_FILE.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)


        writer.writerow([
            "timestamp_utc",
            "computer",
            "channel",
            "event_id",
            "record_id",
            "user",
            "source_ip",
        ])

        for number in range(EVENT_COUNT):
            writer.writerow([
                "2026-10-02T05:33:32+00:00",
                "DESKTOP-SHUTGIN",
                "Security",
                4625,
                number + 1,
                "testuser",
                "192.168.1.10",
            ])


def run_benchmark():
    create_sample_file()

    tracemalloc.start()
    start_time = time.perf_counter()

    processed = sum(1 for event in ingest_file(BENCHMARK_FILE))

    elapsed = time.perf_counter() - start_time
    current_memory, peak_memory = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    print(f"Events processed: {processed:,}")
    print(f"Elapsed time: {elapsed:.2f} seconds")
    print(f"Peak Python memory: {peak_memory / (1024 * 1024):.2f} MB")

    if processed == EVENT_COUNT and elapsed < 60:
        print("Benchmark result: PASS")
    else:
        print("Benchmark result: FAIL")


if __name__ == "__main__":
    run_benchmark()