# how attackur works
No timer: must wait until peer1 has accidentally sent HELLO to attacker instead of peer2, and then create keys with peer1 and peer2
Peer1 --> HELLO  --X Attacker --> HELLO  --> Peer2
Peer1 <-- AGREE  <-- Attacker <-- AGREE  <-- Peer2
Peer1 --> VERIFY --X Attacker --> VERIFY --> Peer2
Peer1 <-- COMM   <-- Attacker <-- COMM   <-- Peer2
