# Smart Contracts Gas optimization techniques

[![Alberto Molina](https://miro.medium.com/v2/resize:fill:55:55/1*lSJbUjOBRll6O9CeKtUE9Q.jpeg)](https://medium.com/@alberto.molina.arribere?source=post_page---byline--2bd07add0e86---------------------------------------)

[![Coinmonks](https://miro.medium.com/v2/resize:fill:30:30/1*-_aiJHzJPz655N7iSSrLrQ.png)](https://medium.com/coinmonks?source=post_page---byline--2bd07add0e86---------------------------------------)

[Alberto Molina](https://medium.com/@alberto.molina.arribere?source=post_page---byline--2bd07add0e86---------------------------------------)·[Follow](https://medium.com/m/signin?actionUrl=https%3A%2F%2Fmedium.com%2F_%2Fsubscribe%2Fuser%2F2625512f5eac&operation=register&redirect=https%3A%2F%2Fmedium.com%2Fcoinmonks%2Fsmart-contracts-gas-optimization-techniques-2bd07add0e86&user=Alberto+Molina&userId=2625512f5eac&source=post_page-2625512f5eac--byline--2bd07add0e86---------------------post_header------------------)

Published in[Coinmonks](https://medium.com/coinmonks?source=post_page---byline--2bd07add0e86---------------------------------------)·10 min read·Jun 17, 2022



38

2







Every time a transaction get’s sent to the blockchain, gas fees must be paid. The amount of gas is related to the amount of computation the transaction requires, in other words, the amount of computation the EVM will have to perform to execute the transaction (in case the transaction does not involve the EVM, a simple Ether transfer for example, the amount of gas is fixed).

> New to trading? Try [crypto trading bots](https://medium.com/coinmonks/crypto-trading-bot-c2ffce8acb2a) or [copy trading](https://medium.com/coinmonks/top-10-crypto-copy-trading-platforms-for-beginners-d0c37c7d698c)

You can design and implement your smart contracts to be **gas efficient**. There are two “*types*” of gas that I will be talking about in this blog:

- **Transaction Gas** : The amount of gas your users will have to pay every time they interact with your smart contract. The idea here is to implement gas efficient functions that consume as little gas as possible.
- **Deployment Gas** : The amount of gas that you will have to pay every time you deploy your smart contracts. Deploying smart contract is something that usually only happens once, but still saving gas can be interesting for you.

Sometimes, techniques to reduce one type of gas can cause the other type of gas to increase, this is a tradeoff you will have to deal with…

![img](https://miro.medium.com/v2/resize:fit:875/1*x9fYUrbnY14lDX9X-npglw.png)

This is a list of things that you should keep in mind when working on your smart contracts in order to save gas.

- **Minimize on-chain data** (events, IPFS, stateless contracts, merkle proofs)
- **Minimize on-chain operations** (strings, return storage value, looping, local storage, batching)
- **Memory Locations** (calldata, stack, memory, storage)
- **Variables ordering**
- **Preferred data types**
- **Libraries** (embedded, deploy)
- **Minimal Proxy**
- **Constructor**
- **Contract size** (messages, modifiers, functions)
- **Solidity compiler optimizer**

# Minimize on-chain data

Saving data on storage memory is expensive, if you manage to reduce the amount of information that you need to store on the blockchain to a minimum, you will be saving a lot of ***transaction\*** Gas.

- **Events** : You can consider using events to “store” data on the blockchain. An event is a piece of information that will actually be stored on the blockchain, only that it will not be part of your contract’s storage, in fact, it will not be possible for smart contracts to read or use events in any way. Events are only available to off-chain applications reading the blockchain. This is why events are not to be used if your smart contract requires that information, but if you just need the data to be persisted on the blockchain only for reading purposes.
- **IPFS** : In case you need to save files (documents, videos, …) in a decentralized way, you should consider IPFS (a distributed, cheap file storage). Each file stored on IPFS will have a unique ID that you can store on the blockchain for reference, but the actual file will be stored in IPFS.
- **Stateless contracts** : If you just need to use the blockchain as a decentralized database to store some “simple” data, like key/value pairs or similar, you can use what it’s called a stateless contract. The idea is to deploy a contract with functions that define some input parameters but do not really store any data on storage. Users will invoke the methods passing the input parameters as part of the transaction data. Transactions will for ever be stored on the blockchain, meaning that you will always be able to read from an off-chain application the content of transactions data (which contains the input parameters). The drawback here is that you will need to implement a robust backend that is able to track and extract those values from the blockchain. Events are easier to track, filter and extract, but they are more expensive.
- **Merkle Proofs** : If you need to use the blockchain to verify if some information is valid or not, you can use merkle proofs. A merkle proof uses a single chunk of data in order to prove the validity of a much larger amount of data. The idea is that you will only need tot store the Merkle tree root on the blockchain (Hash12345678) in order to be able to validate multiple transactions (Tx1 …. Tx8). If for example someone wants to prove “Tx4” validity, he will need to provide Tx4, Hash3, Hash12 and Hash5678, then your contract will be able to recalculate the merkle root (Hash12345678) and check if it corresponds to the one stored on the blockchain. You will not need to store the hashes of all the transactions.

![img](https://miro.medium.com/v2/resize:fit:875/1*u0sArJrVD1TATgmbmLViCA.png)

# Minimize on-chain operations

Only add to your smart contracts the functionality that for security, legal, or any other very good reason, needs to be performed on the blockchain. Keep all the remaining tasks off-chain, in a dedicated backend or even your front end, that way you will save ***transaction\*** gas.

- **Strings** : strings are just bytes to ethereum. Even if both data types exist, the EVM will process strings as bytes, which requires some overhead, meaning that if you can use bytes instead of strings do it. If you still need to use strings, then try to keep string operations (concatenation, etc…) outside of your smart contracts.
- **Return storage values** : if you need to return storage values after executing some functionality. Return it as it is, without transforming it, let the off-chain application retrieving the data do the work (extract certain values from an array etc…).
- **Looping** : avoid looping through long arrays, not only it will cost a lot a gas but it can even make your contract impossible to be executed if gas costs increase to much (beyond the Block gas limit). Use mappings instead which are hash tables that will let you access any value in a single operation using its key, instead of looping through an array until you find the key you are looking for.
- **Local storage** : local storage variables are method local variables that point to an actual state variable (stored in storage). Instead of copy/pasting storage arrays in memory in order to manipulate them, then copying them back to storage, simply use local storage variables and work on the storage directly.
- **Batching** : instead of making your users invoke the same function multiple times with different values (by sending multiple transactions to the blockchain), give them the possibility to pass dynamically sized arrays so that they can execute the same functionality in one single transaction instead. It will allow them to save some overhead costs.

# Memory locations

Ethereum has 4 memory locations, from cheapest to most expensive : calldata, stack, memory and storage. If used properly you will save a lot of ***transaction\*** Gas.

- **Calldata** : only available for **input parameters that happen to be reference data types (arrays, string, …) of external functions**. Calldata arguments are read only, but if you have some reference types that you need to pass to your method, always consider the calldata memory location since it is the **cheapest** one.
- **Stack** : only available for value types that are defined within a method.
- **Memory** : memory is volatile RAM that will be removed the moment the EVM terminates. You can use it to store **reference data types** and it is **cheaper than storage**. When passing arguments to other functions, or declaring temporarily variables in your function, always use memory unless you strictly need to use storage.
- **Storage** : the **most expensive** memory location. Storage data is persisted on the blockchain and as stated in the very first element of this list, you should always minimize on-chain data.

# Variables ordering

Solidity storage slots are 32 bytes long, but not all data types take that amount of space : bool, int8 … int128, bytes1 … bytes31 and addresses take less than 32 bytes.

The solidity compiler will try to pack together variables in a single slot, but these variables need to be defined next to each other.

For example, if you define 2 *int128* next to each other, they will both be packed into the same storage slot since they take 16 bytes each. However if you define an *int128*, followed by a *unit256*, then another *int128*, you will be using 3 storage slots since the unit256 in between the 2 int128 need a full storage slot.

![img](https://miro.medium.com/v2/resize:fit:285/1*ZUWhvnvonDWhJv_dEJL_4Q.png)

![img](https://miro.medium.com/v2/resize:fit:283/1*mKFJ9UE85mJ1uA0iQv8F4g.png)

You will be able to save storage space and ***transaction\*** gas doing this.

# **Preferred data types**

If you are going to define variables that will take a full storage slot, you better use variables that *actually* take the full storage slot.

Let’s explain it with an example.

Our smart contract requires only one state variable, an unsigned integer that will never be bigger than 255. We will be tempted to use *uint8* as the datatype. The problem is that ethereum opcodes are designed to use 256 bits variables (size of the EVM stack), whereas uint8 only take 8 bits, the EVM will then fill the remaining bits with “0” in order to be able to manipulate it. This “0” addition performed by the EVM will cost gas, meaning that in order to save ***transaction\*** gas, it is better to use uint256 instead of uint8.

# Libraries

If you are going to re-use code among your smart contracts then you better pack all that code into a library, deploy it and make your contracts point to it by importing it.

Libraries can be of two types.

- **Embedded Libraries:** libraries that contain internal functionality. These libraries do not get deployed but embedded into your contract, meaning that you will deploy their code along your smart contract code… You will not be re-using anything nor saving any Gas with these type of libraries….
- **Deployed Libraries:** libraries that contain public or external functionality. These libraries get deployed once, then all smart contracts importing them will be actually delegating calls to them. This means that the library code gets deployed only once then used by all smart contracts. You will be saving ***deployment\*** Gas if you use this type of library.

# Minimal Proxies (ERC 1167)

If you are going to need to deploy multiple contracts with exactly the same functionality you should consider using “Minimal Proxies” (defined in the ERC 1167).

A minimal proxy is just a contract that will delegate all its calls to a pre-defined *implementation contract*, nothing else. There is already a well defined byte-code that represents the Minimal proxy contract compiled code, you will simply need to insert your implementation contract address into it and you are ready to deploy as many copies of your minimal proxy as you need.

Since that byte-code is so minimal, the cost of deploying it is as low as it can get, you will be saving a bunch of ***deployment\*** Gas.

There is a caveat with minimal proxies that you should keep in mind: *Minimal proxy implementation contract address cannot be changed, meaning that you will not be able to migrate their code.*

# **Constructor**

The constructor method is executed only once, during the contract creation, but if you manage to simplify it you will be saving ***deployment\*** gas.

- **Constants overs immutable** : constant and immutable state variables cannot be changed after the contract has been deployed. The difference is that constants variable must be defined at compile time whereas immutable can be defined within the constructor. Always try to use constants in order to make the constructor cheaper.

# Contract Size

Contract deployment costs depend on several things, one of them is the size of the contract you are deploying (in KB, keep in mind that there is a limit of 24KB for single contracts).

A simple way to reduce the ***deployment\*** gas, is to implement contracts as small as possible.

- **Logs / Messages** : make revert and assert messages as short as possible.
- **Modifiers** : modifier code is inlined, meaning that it gets added at the beginning and the end of the function it modifies. A trick to reduce the contract size while using modifiers is to write a function that implements the modifier logic, and make the modifier invoke that function. That way the code implementing the modifier functionality will not be replicated, only the function invocation will. This technique only works if the same modifier is used multiple times.

![img](https://miro.medium.com/v2/resize:fit:651/1*HfuOdmmIyDqSLQI95hcXDA.png)

- **Functions** : try to use as few opcodes as possible when implementing your functionality. This is not always possible or even that efficient in terms of gas because some opcodes are more expensive than other, you might be saving deployment gas but increasing transaction gas…

# Solidity compiler optimizer

Do not forget to activate the solidity compiler gas optimizer when compiling your code before deployment. This features tells the compiler to optimize the byte code that will be generated and deployed to the blockchain so that it reduces ***deployment\*** and ***transaction\*** gas.

Overall, the optimizer tries to simplify complicated expressions, which reduces both code size and execution cost. It also specializes or *inlines* functions. Especially function inlining is an operation that can cause much bigger code, but it is often done because it results in opportunities for more simplifications.