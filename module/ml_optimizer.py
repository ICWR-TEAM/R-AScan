import json
import os
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from module.other import Other

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
        text = json.dumps(result).lower()
        if "vulnerable" in text or '"vulnerable": true' in text:
            return 1
        if any(k in text for k in ["payload", "curl", "injection", "leaked"]):
            return 1
        if '"status": 429' in text or "anomaly" in text:
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
        probs = self.predict(texts)

        print(f"[*] [Module: {self.module_name}] [ML Optimization Results]")
        for idx, entry in enumerate(entries):
            module_name = list(entry.keys())[0]
            prob = probs[idx][1]
            label = "Vuln-Likely" if prob > 0.7 else "Safe-Likely"
            confidence = f"{prob * 100:.2f}%"
            color = "green" if label == "Vuln-Likely" else "red"
            colored_name = self.printer.color_text(module_name, "cyan")
            colored_label = self.printer.color_text(f"[Result: {label} ({confidence})]", color)
            print(f"[+] {colored_name} — {colored_label}")

def scan(args=None):
    return MLOptimizer(args).run()
