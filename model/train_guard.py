"""Train the open guard adapter: a LoRA (r16) on fastino/GLiNER2.5-Decide, trained only on the train splits of the two
public labeled sets in ../data (deepset/prompt-injections and 3nesdeniz/agentic-prompt-injection-boundary-pairs, both
CC-BY-4.0). The labels are the datasets' own human labels; no model output is used as a label.
Usage (from model/): python train_guard.py 360 ck   # 360 steps, batch 1 x 8, about 8 minutes on an M4 Pro"""
import json, random, sys, torch
from gliner2 import AutoExtractor
from gliner2.training.data import Classification, InputExample
from gliner2.training.trainer import ExtractorTrainer, TrainingConfig
steps, out = int(sys.argv[1]), sys.argv[2]
LABELS = ["injection", "benign"]
rows = [json.loads(l) for f in ("../data/boundary_train.jsonl", "../data/deepset_train.jsonl") for l in open(f) if l.strip()]
ex = [InputExample(text=r["text"][:3000], classifications=[Classification(
    task="injection", labels=LABELS, true_label=LABELS[0] if r["label"] else LABELS[1])]) for r in rows]
random.Random(7).shuffle(ex)
print(len(ex), "examples", sum(r["label"] for r in rows), "injections", flush=True)
m = AutoExtractor.from_pretrained("fastino/GLiNER2.5-Decide")
if torch.backends.mps.is_available():
    def _mps(self):
        self.device, self.is_distributed = torch.device("mps"), False
        self.model.to(self.device)
    ExtractorTrainer._setup_device = _mps
cfg = TrainingConfig(output_dir=out, num_epochs=3, max_steps=steps, batch_size=1, gradient_accumulation_steps=8,
                     gradient_checkpointing=True, max_len=400, use_lora=True, lora_r=16, save_adapter_only=False,
                     eval_strategy="no", logging_steps=10, num_workers=0, pin_memory=False, fused_optimizer=False,
                     task_lr=5e-4, encoder_lr=5e-5)
print(ExtractorTrainer(m, cfg).train(train_data=ex))
m.save_pretrained(f"{out}/final")
