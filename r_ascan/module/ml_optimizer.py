import json
import os
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from r_ascan.module.other import Other

class MLOptimizer:
    def __init__(self, args):
        self.args = args
        self.output_path = args.output or f"scan_output-{args.target}.json"
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()
        self.model = RandomForestClassifier()
        self.vectorizer = TfidfVectorizer()

    def extract_features(self, entries):
        texts = []
        labels = []
        for entry in entries:
            module_name = list(entry.keys())[0]
            result = entry[module_name]
            text = json.dumps(result)
            label = self.auto_label(result)
            texts.append(text)
            labels.append(label)
        return texts, labels

    def auto_label(self, result):
        if isinstance(result, dict):
            flat = json.dumps(result).lower()
            if '"vulnerable": true' in flat:
                return 1
            if "missing" in result and isinstance(result["missing"], list):
                if len(result["missing"]) >= 3:
                    return 1
            if "curl" in flat and ("chunked" in flat or "payload" in flat):
                return 1
            if "match" in flat and "payload" in flat and "7*7" in flat:
                return 1
            if "status_line" in flat and "429" in flat and "anomaly" in flat:
                return 1
            if "findings" in result:
                for finding in result["findings"]:
                    if finding.get("vuln") is True:
                        return 1
            if "potential_bac" in result:
                if any(r.get("status") in [200, 201, 202, 203, 204, 206, 207] for r in result["potential_bac"]):
                    return 1
            if "access_control_results" in result:
                for r in result["access_control_results"]:
                    if isinstance(r, dict) and r.get("status_code") in [200, 201, 202, 204]:
                        return 1
            if any(k in flat for k in ["injection", "leak", "anomaly", "payload"]):
                return 1
        elif isinstance(result, list):
            for item in result:
                if self.auto_label(item) == 1:
                    return 1
        return 0

    def train_model(self, texts, labels):
        X = self.vectorizer.fit_transform(texts)
        self.model.fit(X, labels)

    def predict(self, texts):
        X = self.vectorizer.transform(texts)
        return self.model.predict_proba(X)

    def run(self):
        if not os.path.exists(self.output_path):
            print(f"[!] Scan result not found: {self.output_path}")
            return

        with open(self.output_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        entries = data.get("result", [])
        texts, labels = self.extract_features(entries)

        if len(set(labels)) < 2:
            print("[!] Not enough variance in data for ML training.")
            return

        self.train_model(texts, labels)
        probabilities = self.predict(texts)
        colored_module = self.printer.color_text(self.module_name, "cyan")
        print(f"[*] [Module: {colored_module}] [ML Optimization Results]")
        for idx, entry in enumerate(entries):
            module_name = list(entry.keys())[0]
            prob = probabilities[idx][1]
            label = "Vuln-Likely" if prob > 0.7 else "Safe-Likely"
            confidence = f"{prob * 100:.2f}%"
            colored_name = self.printer.color_text(module_name, "cyan")
            colored_label = self.printer.color_text(label, "green" if label == "Vuln-Likely" else "red")
            print(f"[+] [Module: {colored_name}] — [Result: {colored_label} ({confidence})]")

def scan(args=None):
    return MLOptimizer(args).run()
