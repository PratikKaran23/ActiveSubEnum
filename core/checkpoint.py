"""
core/checkpoint.py — Real-time Checkpoint + Resume for Long Scans

Provides:
  CheckpointManager — Save scan progress every N words so interrupted
    scans can be resumed without losing work.

Usage:
  ckpt = CheckpointManager(domain, output_dir="results")

  # On --resume: load previous state
  state = ckpt.load()
  if state:
      skip = state["words_done"]
      pre_populate = state["found_so_far"]
      remaining = ckpt.get_remaining_words(full_wordlist)

  # In brute force loop:
  if ckpt.should_checkpoint(word_idx, len(wordlist)):
      ckpt.save_progress("bruteforce", word_idx, len(wordlist), found_so_far)

  # After successful scan:
  ckpt.clear()

The checkpoint file (.checkpoint_{domain}.json) is written atomically
to avoid corruption on interrupt.
"""

import json
import os
import time
from typing import Any, Dict, List, Optional


class CheckpointManager:
    """Save and restore scan state for resumable brute force.

    The checkpoint file is written atomically (write to .tmp, then rename)
    to prevent corruption if the process is killed mid-write.
    """

    def __init__(
        self,
        domain: str,
        checkpoint_dir: str = "results",
        checkpoint_every: int = 500,
    ):
        self.domain = domain
        self.checkpoint_dir = checkpoint_dir
        self.checkpoint_every = checkpoint_every
        # Sanitize domain for use in filename
        safe_domain = domain.replace(".", "_")
        self.checkpoint_file = os.path.join(
            checkpoint_dir, f".checkpoint_{safe_domain}.json"
        )
        self._last_save = 0.0

    def _should_save(self) -> bool:
        """Rate-limit saves to max once per 5 seconds."""
        return time.time() - self._last_save >= 5.0

    def should_checkpoint(self, words_done: int, words_total: int) -> bool:
        """Returns True if a checkpoint should be written now."""
        if words_done == 0:
            return False
        if words_done % self.checkpoint_every == 0 and self._should_save():
            return True
        # Also checkpoint near end
        if words_total - words_done < self.checkpoint_every:
            return self._should_save()
        return False

    def save_progress(
        self,
        technique: str,
        words_done: int,
        words_total: int,
        found_so_far: Dict[str, Dict],
    ):
        """Write current state to checkpoint file.

        Args:
            technique: current technique name (e.g. "bruteforce")
            words_done: number of words already processed
            words_total: total words in the wordlist
            found_so_far: dict of {fqdn: {"ips": [...], "techniques": [...]}}
        """
        pct = round(words_done / words_total * 100, 2) if words_total else 0.0

        state = {
            "domain": self.domain,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "technique": technique,
            "words_done": words_done,
            "words_total": words_total,
            "progress_pct": pct,
            "found_so_far": found_so_far,
            "found_count": len(found_so_far),
        }

        tmp = self.checkpoint_file + ".tmp"
        try:
            os.makedirs(self.checkpoint_dir, exist_ok=True)
            with open(tmp, "w") as f:
                json.dump(state, f, indent=2)
            os.replace(tmp, self.checkpoint_file)
            self._last_save = time.time()
        except Exception:
            pass

    def save(
        self,
        words_done: int,
        words_total: int,
        found_subdomains: List[str],
        resolver_pool: Optional[List[str]] = None,
        extra: Optional[Dict[str, Any]] = None,
    ):
        """Legacy alias for save_progress()."""
        found_dict: Dict[str, Any] = {
            sub: {"ips": [], "techniques": ["checkpoint"]}
            for sub in found_subdomains
        }
        self.save_progress("bruteforce", words_done, words_total, found_dict)

    def load(self) -> Optional[Dict[str, Any]]:
        """Load checkpoint state if it exists and is valid.

        Returns None if no checkpoint exists or if it belongs to a
        different domain/wordlist.
        """
        if not os.path.exists(self.checkpoint_file):
            return None
        try:
            with open(self.checkpoint_file) as f:
                state = json.load(f)
            if state.get("domain") != self.domain:
                return None
            return state
        except Exception:
            return None

    def get_remaining_words(self, full_wordlist: List[str]) -> List[str]:
        """Return the portion of the wordlist not yet processed.

        Requires that load() has been called first so that words_done
        is known. If no checkpoint exists, returns the full wordlist.

        Args:
            full_wordlist: the complete wordlist (list of words)

        Returns:
            Words from words_done index onwards
        """
        state = self.load()
        if not state:
            return list(full_wordlist)

        words_done = state.get("words_done", 0)
        total = state.get("words_total", 0)

        # If total changed (different wordlist), ignore checkpoint
        if total != len(full_wordlist):
            return list(full_wordlist)

        return full_wordlist[words_done:]

    def clear(self):
        """Remove checkpoint file after successful completion."""
        try:
            if os.path.exists(self.checkpoint_file):
                os.remove(self.checkpoint_file)
        except Exception:
            pass

    def progress_str(self, words_done: int, words_total: int) -> str:
        """Return a human-readable progress string."""
        pct = words_done / words_total * 100 if words_total else 0.0
        return f"{words_done:,}/{words_total:,} ({pct:.1f}%)"