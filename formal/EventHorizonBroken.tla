----------------------- MODULE EventHorizonBroken -----------------------
EXTENDS FiniteSets

CONSTANT Authority
VARIABLES compiled, guardian

vars == <<compiled, guardian>>

Init == /\ compiled = {CHOOSE a \in Authority: TRUE}
        /\ guardian = compiled

BrokenGuardianAddsAuthority ==
    /\ guardian' = Authority
    /\ UNCHANGED compiled

Next == BrokenGuardianAddsAuthority
Spec == Init /\ [][Next]_vars

GuardianNeverAddsAuthority == guardian \subseteq compiled

=============================================================================
