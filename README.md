# Bitcoin Puzzle Focus #71

## Download
https://github.com/ADDAddition/btc-puzzle-focus71/archive/refs/heads/main.zip

## PowerShell (une commande)
```powershell
git clone https://github.com/ADDAddition/btc-puzzle-focus71.git; cd btc-puzzle-focus71; npm install; python -m pip install coincurve; Start-Process powershell -ArgumentList '-NoExit','-Command','$env:FOCUS71=1; python -u scripts/focus71_pubkey_kangaroo.py'; npm run dev -- -p 3456
```

Ouvre http://localhost:3456

## Focus #71 (pubkey → kangaroo)
```bash
bash scripts/run_focus71.sh
# ou si tu as la pubkey:
FOCUS71_PUBKEY=<hex> python3 -u scripts/focus71_pubkey_kangaroo.py
```

Adresse #71: `1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU`  
Range: `2^70` … `2^71-1`  
Sans pubkey = attente. Avec pubkey = kangaroo C.
