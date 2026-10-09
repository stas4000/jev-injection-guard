# OpenBles naming

OpenBles is the family name of what Bles Software releases in the open: weights, code and the numbers behind them.

| Thing | Rule | Example |
|---|---|---|
| Family | Always `OpenBles`, one word | OpenBles |
| Model | `OpenBles <Job> <generation>`. The job is one plain word for the decision the model makes | OpenBles Firewall 1 |
| Repo | `openbles-<job>`, lower case. The generation is a folder or a tag, never a new repo | `openbles-firewall` |
| Weights | In `model/` of the repo, with the loader and the training and eval scripts beside them | `model/adapter.safetensors` |
| First mention in text | Name, size, what it is, base model | "OpenBles Firewall 1, a 31.8 MB open decision model built on GLiNER2.5-Decide" |

Rules that hold for every release:

1. The name says the job, never the vendor of a model we compared against.
2. A new generation (2, 3) means new weights with a new measured table on the same held-out sets.
3. Every release states its base model and license, the data it learned from, and one table measured on data it never trained on.
4. Trained on public or outcome labels only. No labels that are another vendor's model answers.
