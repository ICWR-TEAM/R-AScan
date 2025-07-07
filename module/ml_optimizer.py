import json
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from module.other import Other

class MLOptimizer:
    def __init__(self, args):
        self.args = args
        self.output_path = args.output or f"scan_output-{args.target}.json"
        self.module_name = os.path.splitext(os.path.basename(__file__))[0]
        self.printer = Other()
        self.model = LogisticRegression()
        self.vectorizer = TfidfVectorizer()

    def extract_features(self, entries):
        texts = []
        labels = []
        for entry in entries:
            for module_name, result in entry.items():
                text = json.dumps(result)
                texts.append(text)
                label = 1 if "vuln" in text.lower() or "vulnerable" in text.lower() else 0
                labels.append(label)
        return texts, labels

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

        data = json.load(open(self.output_path, "r"))
        entries = data.get("result", [])
        texts, labels = self.extract_features(entries)

        if len(set(labels)) < 2:
            print("[!] Not enough variance in data for ML training.")
            return

        self.train_model(texts, labels)
        probabilities = self.predict(texts)

        print(f"[*] [Module: {self.module_name}] [ML Optimization Results]")
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
