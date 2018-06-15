./geth --identity "ETH-MainNode" --rpc --rpcport "8545" --rpccorsdomain "*" --datadir "./chain" --port "65520" --nodiscover --maxpeers 5 --rpcapi "admin,db,eth,debug,miner,net,shh,txpool,personal,web3" --networkid 3131 console --dev


#geth --identity "ETH-MainNode" --rpc --rpcport "8545" --rpccorsdomain "*" --datadir "./chain" --port "65520" --nodiscover --maxpeers 5 --rpcapi "admin,db,eth,debug,miner,net,shh,txpool,personal,web3" --networkid 3131 console