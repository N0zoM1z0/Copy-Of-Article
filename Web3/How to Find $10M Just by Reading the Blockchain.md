Two weeks ago, one Golem enthusiast and GNT holder reported a strange [GNT transfer transaction](https://etherscan.io/tx/0x0213fb70e8174c5cbd9233a8e95905462cd7f1b498c12ff5e8ec071f4cc99347) bug. After investigating the data attached to the transaction, I discovered that there *had* to be a problem in the way the exchange was preparing data for the transaction. “*Oh no,”* I thought, “*this bug could be used to empty the whole GNT account on the exchange!”* And quite a large number of tokens were stored there!

The bug was indeed the exchange’s fault, but it was also related to the way Ethereum contracts see the transaction input data and Solidity ABI (e.g. the way the methods of Solidity contracts encode and decode arguments). So of course it was not specific to GNT, but indeed to *all* ERC20 tokens, as well as other contracts which have transfer-like methods. Yes you read it right: this could potentially work for *any* Ethereum-based token listed on said exchange, if only withdrawals were managed in the same way as GNT. We do not know this to be the case, but assume it was very likely.

# Ethereum Contract ABI

Raw Ethereum contracts have neither methods nor functions. Methods are features of high level languages like Solidity, and they use the Ethereum Contract ABI to specify how a contract’s bytecode is divided into methods, as well as how different types of arguments are encoded in transaction input data. *(See* [*https://github.com/ethereum/wiki/wiki/Ethereum-Contract-ABI*](https://github.com/ethereum/wiki/wiki/Ethereum-Contract-ABI) *for a reference.)*

To invoke the `transfer(address a, uint v)` method of the GNT contract to transfer 1 GNT to address `0xabcabcabcabcabcabcabcabcabcabcabcabcabca` one needs to include 3 pieces of data:

- 4 bytes, being the method id: `a9059cbb`
- 32 bytes, with the destination address (20 bytes) filled with leading zeros: `000000000000000000000000abcabcabcabcabcabcabcabcabcabcabcabcabca`
- 32 bytes, being the value to transfer, 1 * 10¹⁸ GNT: `0000000000000000000000000000000000000000000000000de0b6b3a7640000`

The full transaction would therefore look like this: `a9059cbb000000000000000000000000abcabcabcabcabcabcabcabcabcabcabcabcabca0000000000000000000000000000000000000000000000000de0b6b3a7640000`.

# Transaction input data is infinite

This is one of the messier aspects of the Ethereum Virtual Machine, but it is critical to understanding the issue fully. The EVM can read bytes of any given input data offset using `CALLDATALOAD`opcode. If the data in this offset is not provided in the transaction by the transaction creator, the EVM will get zeros as the answer. At the same time, the contract is able to check the real length of the provided transaction input data with the `CALLDATASIZE` opcode.

# The bug

The service preparing the data for token transfers assumed that users will input 20-byte long addresses, but the length of the addresses was not actually checked. In the aforementioned transaction, the user filled in an invalid address of a shorter length: `79735`. The resulting data was malformed because the address argument took 14.5 bytes (12 bytes for leading zeros + 4.5 bytes from user input). To be precise, the transaction data was fine for the Ethereum platform as it does not care about data included in the transactions except applying fee for every byte. The only reason why the token transfer was not executed by the GNT contract was that the amount in the transaction was ridiculously high (higher than the total supply, and *of course* higher than the balance of the address in question). The owner of the address was really quite lucky in that the user used such a short string for the address: with some (bad) luck, the user would be able to ******incidentally\***** empty the address of all GNT and send them to some random address*. This is when we realized that bug could also be used for attack, and was very serious.

# The possible attack

As you may have noticed, allowing a user to input a shorter transfer address shifts the “amount of tokens to transfer” value to the left, making the value larger. It is also very easy to find a private key to an Ethereum address with zeros in the end of the address, e.g. `0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000`.

Therefore, the owner of this address can enter `0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` (skipping zeros) in the service interface. The attacker could then order a transfer of some value X from the service, to the inserted malformed address. This would actually cause a transfer of a value shifted by 16 bits, i.e. 65536 times larger than X, to attacker’s Ethereum account!

# What we have done about it?

Once identifying the possible attack, we contacted the exchange and informed them about the bug. That was a surprisingly difficult and annoying process; our CEO Julian had a call with a support line whose representative didn’t want to listen, and continued shouting that bugs are not his business, and was refusing to redirect us further up in the chain of command. Eventually however, after couple of hours of this, Alex managed to put us through to the CEO level, and our message went through. Once we heard confirmation that bug was fixed, we reached out to other exchanges. While we had no reason to assume that they were vulnerable, we also had no reason to assume the opposite. While we have to admit that we have not tested that for other exchanges or other tokens, we were shocked and a little bit terrified to realize the potential consequences of someone taking advantage of that bug for multiple tokens on multiple exchanges: The entire Ethereum token economy and startup ecosystem might be set back by years.

# What can Ethereum do about this?

While I don’t think the Ethereum developers can do much more than continuing to educate the public about how the Ethereum actually works, we might suggest additional checks added in the future versions of Solidity, for example validating that the transaction input data length matches the expected data for the given contract method.

# What should exchanges absolutely do about this?

1. Verify user input as strictly as possible. Simply checking the length of an address provided by a user secures them from the described attack. Moreover, validate the Ethereum address checksum if available (see [EIP55](http://ethereum.stackexchange.com/a/1379/489)), or even accept addresses *exclusively* with checksums. This both increases both security and user-friendliness.
2. Make sure that transaction data is properly encoded.
3. The generated transaction data might be also parsed back and checked against given user input.
4. Check if other parameters like gas, gas price, and the destination address of the generated transaction matches the expected values.