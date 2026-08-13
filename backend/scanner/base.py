from abc import ABC, abstractmethod


class ScannerBase(ABC):
    """
    అన్ని scanner adapters కోసం common interface.
    """

    @abstractmethod
    async def scan(self, target: str) -> list[dict]:
        """
        ఇచ్చిన targetపై scan చేసి findings list return చేయాలి.
        """
        raise NotImplementedError
