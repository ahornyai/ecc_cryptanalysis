from abc import ABC, abstractmethod

class ECDSAttack(ABC):

    def required_signatures(self) -> int:
        return 2

    def max_signatures(self) -> int: # All of them by default
        return 2**63-1 

    @abstractmethod
    def attack(self, signatures, pubkey, curve, generator) -> int | None:
        pass

    def find_known_part_length(self, signatures):
        kp_length = 0

        for kp in signatures["kp"]:
            kp_length += kp.bit_length()

        return kp_length // len(signatures["kp"]) + 1 # upper bound

    def __str__(self) -> str:
        return "Untitled ECDSA attack"