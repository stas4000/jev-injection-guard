"""Load the open guard: GLiNER2.5-Decide with the adapter folded in (W + alpha/r * B@A). Usage in code:
    from load_guard import load; m = load("model")   # then m.classify_text(text, {"injection": {"labels": ["injection", "benign"]}})"""
import json, os, tempfile
import torch
from gliner2 import AutoExtractor
from safetensors.torch import load_file, save_file

BASE = "fastino/GLiNER2.5-Decide"


def load(adapter_dir: str, device: str | None = None):
    cfg = json.load(open(os.path.join(adapter_dir, "lora_config.json")))
    scale = cfg["lora_alpha"] / cfg["lora_r"]
    lora = load_file(os.path.join(adapter_dir, "adapter.safetensors"))
    m = AutoExtractor.from_pretrained(BASE)
    state = m.state_dict()
    for key in [k for k in lora if ".lora_A." in k]:
        pre = key.split(".lora_A.")[0]
        target = pre + ".weight"
        a, b = lora[key].float(), lora[key.replace(".lora_A.", ".lora_B.")].float()
        state[target] = (state[target].float() + scale * (b @ a)).to(state[target].dtype)
    m.load_state_dict(state)
    device = device or ("cuda" if torch.cuda.is_available() else "mps" if torch.backends.mps.is_available() else "cpu")
    return m.to(device).eval()
