# Auctions

[PT]  
Projeto desenvolvido no âmbito da cadeira Redes de Computadores (RC) do Instituto Superior Técnico (IST).
O enunciado pode ser encontrado na diretoria raiz do repositório (statement.pdf).

[EN]  
Project developed within the scope of the Computer Networks course of Instituto Superior Tecnico (IST).
The statement can be found in the root directory of this repository (statement.pdf).

> The goal of this project is to implement a simple auction platform.
> Users can open (host) an auction to sell some asset, and close it, as well list ongoing auctions and make bids.
> The development of the project requires implementing an Auction Server (AS) and a User Application (User).
> The AS and multiple User application instances are intended to operate simultaneously on different machines connected to the Internet.

### Commands

- `login <uid> <password>`
- `logout`
- `unregister`
- `exit`
- `open <name> <fname> <start-value> <timeactive>`
- `close <aid>`
- `myauctions | ma`
- `mybids | mb`
- `list | l`
- `show_asset <aid> | sa <aid>`
- `bid <aid> <value> | b <aid> <value>`
- `show_record <aid> | sr <aid>`

### Protocol (UDP Request) (Client-Server)

- `LIN <uid> <password>`
- `LOU <uid> <password>`
- `UNR <uid> <password>`
- `LMA <uid>`
- `LMB <uid>`
- `LST`
- `SRC <aid>`

### Protocol (UDP Reply) (Server-Client)

- `RLI <status>`
- `RLO <status>`
- `RUR <status>`
- `RMA <status>[ <aid> <state>]*`
- `RMB <status>[ <aid> <state>]*`
- `RLS <status>[ <aid> <state>]*`
- `RRC <status>
      [<host-uid> <auc-name> <fname> <start-value> <date> <time> <timeactive>]
      [B <bidder-uid> <bid-value> <bid-date> <bid-time> <bid-time-elapsed>]
      [E <end-date> <end-time> <end-elapsed-time>]`

### Protocol (TCP Request) (Client-Server)

- `OPA <uid> <password> <name> <start-value> <timeactive> <fname> <fsize> <fdata>`
- `CLS <uid> <password> <aid>`
- `SAS <aid>`
- `BID <uid> <password> <aid> <value>`

### Protocol (TCP Reply) (Server-Client)

- `ROA <status>[ aid]`
- `RCL <status>`
- `RSA <status>[ <fname> <fsize> <fdata>]`
- `RBD <status>`

### Auction Server File Structure
```
  (root)
  |- USERS
  |  |- (uid1)
  |  |  |- (uid1)_pass.txt     < password
  |  |  |- (uid1)_login.txt
  |  |  |- HOSTED
  |  |  |  |- (aid1).txt
  |  |  |  \- (aid2).txt
  |  |  \- BIDDED
  |  |     |- (aid3).txt
  |  |     \- (aid4).txt
  |  |- (uid2)
  |  \- (uid3)
  \- AUCTIONS
     |- (aid1)
     |  |- START_(aid1).txt    < uid name fname value timeactive datetime fulltime
     |  |- ASSET
     |  |  \- (asset_fname1)
     |  |- END_(aid1).txt      < datetime sec_time
     |  \- BIDS
     |     |- (bid_value1).txt < uid value datetime sec_time
     |     |- (bid_value2).txt
     |     \- (bid_value3).txt
     |- (aid2)
     \- (aid3)
```

### Auxiliary Files and Directories

- directory "assets": asset files to use in open command;
- files auction.c/auction.h: functions to validate the parameters of the various commands;
- files utils.c/utils.h: useful functions to read and write to files and sockets;
- files database.c/database.h: functions to manage the AS database;
- directory "output": only created by command show_asset, where it stores the downloaded asset files;

### Timeouts

- to change AS timeout, change the TIMEOUT macro in server.c
- to change User timeout, change the TIMEOUT macro in user.c
