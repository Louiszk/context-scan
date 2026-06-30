import json
from datasets import load_dataset
from pathlib import Path


def load_injection_datasets():
    """Loads jayavibhav/prompt-injection and rikka-snow/prompt-injection-multilingual and combines them."""
    datasets_to_load = ["jayavibhav/prompt-injection", "rikka-snow/prompt-injection-multilingual"]

    combined_data = []

    for repo in datasets_to_load:
        print(f"Loading dataset '{repo}'...")
        try:
            dataset = load_dataset(repo)
            for split in dataset.keys():
                for entry in dataset[split]:
                    text = entry.get("text")
                    if text is None:
                        text = entry.get("prompt")

                    label = entry.get("label")
                    if label is None:
                        label = entry.get("is_injection")

                    if text is not None and label is not None:
                        combined_data.append({"text": text, "label": int(label)})
        except Exception as e:
            print(f"Error loading {repo}: {e}")

    if combined_data:
        output_path = Path(__file__).parent / "training_data.json"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(combined_data, f, ensure_ascii=False, indent=4)
        print(f"Successfully saved {len(combined_data)} samples to {output_path}")


if __name__ == "__main__":
    load_injection_datasets()
