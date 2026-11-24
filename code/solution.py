# Sinthia Ledezma - Assignment 8
import json

def analyze_capture_records(records):
    report = {
        "protocols": {},
        "unique_destinations": []
    }
    unique_dsts = set()

    for pkt in records:
        proto = pkt.get("proto", "UNKNOWN").upper()
        report["protocols"][proto] = report["protocols"].get(proto, 0) + 1
        
        if "dst" in pkt:
            unique_dsts.add(pkt["dst"])
    report["unique_destinations"] = sorted(unique_dsts)
    return report

# Execution on your live Wireshark capture
if __name__ == "__main__":
    with open("capture.json", "r") as f:
        data = json.load(f)
    # Handles both raw packet lists and Wireshark's nested JSON layers
    summary = analyze_capture_records(data)
    print("LIVE CAPTURE SUMMARY:")
    print(summary)
