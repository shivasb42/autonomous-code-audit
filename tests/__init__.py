import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

# Tests never call the Anthropic API or read a real saved key. Subprocesses inherit this.
os.environ["AUDIT_AGENT_OFFLINE"] = "1"
os.environ["AUDIT_AGENT_CREDENTIALS"] = str(Path(__file__).resolve().parent / "no-such-credentials-file")
os.environ.pop("ANTHROPIC_API_KEY", None)
# Test copies made to reproduce findings go to a temporary folder, never ~/.audit-agent/verify.
os.environ["AUDIT_AGENT_WORK"] = tempfile.mkdtemp(prefix="audit-agent-work-")
# Tests never run the real `gh` either; ones that need it point this at a fake.
os.environ["AUDIT_AGENT_GH"] = str(Path(__file__).resolve().parent / "no-such-gh")
