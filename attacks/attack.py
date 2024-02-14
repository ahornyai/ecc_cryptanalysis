from abc import ABC, abstractmethod

class ECDSAttack(ABC):

    def required_signatures(self) -> int:
        return 2

    def max_signatures(self) -> int: # All of them by default
        return 2**63-1 

    @abstractmethod
    def attack(self, signatures, pubkey, curve, generator) -> int | None:
        pass

    def __str__(self) -> str:
        return "Untitled ECDSA attack"