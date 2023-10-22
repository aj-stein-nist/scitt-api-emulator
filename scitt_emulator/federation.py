import json
import dataclasses
from pathlib import Path
from abc import ABC, abstractmethod
from typing import Optional

from scitt_emulator.signals import SCITTSignals, SCITTSignalsFederationCreatedEntry


class SCITTFederation(ABC):
    def __init__(self, app, signals: SCITTSignals, config_path: Path):
        self.app = app
        self.signals = signals
        self.connect_signals()
        self.config = {}
        if config_path and config_path.exists():
            self.config = json.loads(config_path.read_text())

    def __call__(self, environ, start_response):
        return self.app(environ, start_response)

    def connect_signals(self):
        self.created_entry = self.signals.federation.created_entry.connect(self.created_entry)

    @abstractmethod
    def created_entry(
        self,
        created_entry: SCITTSignalsFederationCreatedEntry,
    ):
        raise NotImplementedError
