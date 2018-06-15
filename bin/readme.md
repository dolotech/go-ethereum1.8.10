--datadir "./chain" --networkid 314590  --port 65520  --rpc --rpcapi "web3,eth,net" --rpccorsdomain "*" --rpcport 8545 console



./geth --identity "ETH-MainNode" --rpc --rpcport "8545" --rpccorsdomain "*" --datadir "./chain" --port "65520" --nodiscover --maxpeers 5 --rpcapi "admin,db,eth,debug,miner,net,shh,txpool,personal,web3" --networkid 3131 console
