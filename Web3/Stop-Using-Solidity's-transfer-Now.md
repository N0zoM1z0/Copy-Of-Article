It looks like [EIP 1884](https://eips.ethereum.org/EIPS/eip-1884) is headed our way in the [Istanbul hard fork](https://eips.ethereum.org/EIPS/eip-1679). This change increases the gas cost of the `SLOAD` operation and therefore [*breaks some existing smart contracts*](https://docs.google.com/presentation/d/1IiRYSjwle02zQUmWId06Bss8GrxGyw6nQAiZdCRFEPk/edit).

Those contracts will break because their fallback functions used to consume less than 2300 gas, and they’ll now consume more. Why is 2300 gas significant? It’s the amount of gas a contract’s fallback function receives if it’s called via [Solidity’s `transfer()` or `send()` methods](https://solidity.readthedocs.io/en/v0.5.11/units-and-global-variables.html#members-of-address-types). [1](https://diligence.consensys.io/blog/2019/09/stop-using-soliditys-transfer-now/#fn:1)

Since its introduction, `transfer()` has typically been recommended by the security community because it helps guard against reentrancy attacks. This guidance made sense under the assumption that gas costs wouldn’t change, but that assumption turned out to be incorrect. We now recommend that `transfer()` and `send()` be avoided.

## Gas Costs Can and Will Change

Each opcode supported by the EVM has an associated gas cost. For example, `SLOAD`, which reads a word from storage, currently—but not for long—costs 200 gas. The gas costs aren’t arbitrary. They’re meant to reflect the underlying resources consumed by each operation on the nodes that make up Ethereum.

From the EIP’s [motivation section](https://eips.ethereum.org/EIPS/eip-1884#motivation):

> An imbalance between the price of an operation and the resource consumption (CPU time, memory etc) has several drawbacks:
>
> - It could be used for attacks, by filling blocks with underpriced operations which causes excessive block processing time.
> - Underpriced opcodes cause a skewed block gas limit, where sometimes blocks finish quickly but other blocks with similar gas use finish slowly.
>
> If operations are well-balanced, we can maximise the block gaslimit and have a more stable processing time.

`SLOAD` has historically been underpriced, and EIP 1884 rectifies that.

## Smart Contracts Can’t Depend on Gas Costs

If gas costs are subject to change, then smart contracts can’t depend on any particular gas costs.

Any smart contract that uses `transfer()` or `send()` is taking a hard dependency on gas costs by forwarding a fixed amount of gas: 2300.

Our recommendation is to stop using `transfer()` and `send()` in your code and switch to using `call()` instead:

```solidity
contract Vulnerable {
    function withdraw(uint256 amount) external {
        // This forwards 2300 gas, which may not be enough if the recipient
        // is a contract and gas costs change.
        msg.sender.transfer(amount);
    }
}

contract Fixed {
    function withdraw(uint256 amount) external {
        // This forwards all available gas. Be sure to check the return value!
        (bool success, ) = msg.sender.call.value(amount)("");
        require(success, "Transfer failed.");
    }
}
```

Other than the amount of gas forwarded, these two contracts are equivalent.

## What About Reentrancy?

This was hopefully your first thought upon seeing the above code. The whole reason `transfer()` and `send()` were introduced was to address the cause of the infamous hack on [The DAO](https://en.wikipedia.org/wiki/The_DAO_(organization)). The idea was that 2300 gas is enough to emit a log entry but insufficient to make a reentrant call that then modifies storage.

Remember, though, that gas costs are subject to change, which means this is a bad way to address reentrancy anyway. Earlier this year, [the Constantinople fork was delayed](https://blog.ethereum.org/2019/01/15/security-alert-ethereum-constantinople-postponement/) because *lowering* gas costs caused code that was previously safe from reentrancy to no longer be.

If we’re not going to use `transfer()` and `send()` anymore, we’ll have to protect against reentrancy in more robust ways. Fortunately, there are good solutions for this problem.

### Checks-Effects-Interactions Pattern

The simplest way to eliminate reentrancy bugs is to use the [*checks-effects-interactions pattern*](https://solidity.readthedocs.io/en/v0.5.11/security-considerations.html#re-entrancy). Here’s a classic example of a reentrancy bug:

```solidity
 1contract Vulnerable {
 2    ...
 3
 4    function withdraw() external {
 5        uint256 amount = balanceOf[msg.sender];
 6        (bool success, ) = msg.sender.call.value(amount)("");
 7        require(success, "Transfer failed.");
 8        balanceOf[msg.sender] = 0;
 9    }
10}
```

If `msg.sender` is a smart contract, it has an opportunity on line 6 to call `withdraw()` again *before line 7 happens*. In that second call, `balanceOf[msg.sender]` is still the original amount, so it will be transferred again. This can be repeated as many times as necessary to drain the smart contract.

The idea of the checks-effects-interactions pattern is to make sure that all your *interactions* (external calls) happen at the end. A typical fix for the above code is as follows:

```solidity
 1contract Fixed {
 2    ...
 3
 4    function withdraw() external {
 5        uint256 amount = balanceOf[msg.sender];
 6        balanceOf[msg.sender] = 0;
 7        (bool success, ) = msg.sender.call.value(amount)("");
 8        require(success, "Transfer failed.");
 9    }
10}
```

Notice that in this code, the balance is zeroed out *before* the transfer, so attempting to make a reentrant call to `withdraw()` will not benefit an attacker.

### Use a Reentrancy Guard

Another approach to preventing reentrancy is to explicitly check for and reject such calls. Here’s a simple version of a reentrancy guard so you can see the idea:

```solidity
 1contract Guarded {
 2    ...
 3
 4    bool locked = false;
 5
 6    function withdraw() external {
 7        require(!locked, "Reentrant call detected!");
 8        locked = true;
 9        ...
10        locked = false;
11    }
12}
```

With this code, if a reentrant call is attempted, the `require` on line 7 will reject it because `lock` is still set to `true`.

A more sophisticated and gas-efficient version of this can be found in [OpenZeppelin’s `ReentrancyGuard`](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/ReentrancyGuard.sol) contract. If you inherit from `ReentrancyGuard`, you just need to decorate functions with `nonReentrant` to prevent reentrancy.

Please note that this method only protects you ***if you explicitly apply it to all the right functions***. It also carries an increased gas cost due to the need to persist a value in storage.

## What About Vyper?

[Vyper’s `send()` function](https://vyper.readthedocs.io/en/v0.1.0-beta.12/built-in-functions.html#send) uses the same hardcoded gas stipend as Solidity’s `transfer()`, so it too is to be avoided. You can use [`raw_call`](https://vyper.readthedocs.io/en/v0.1.0-beta.10/built-in-functions.html#raw-call) instead.

Vyper has a [`@nonreentrant()` decorator](https://vyper.readthedocs.io/en/v0.1.0-beta.12/structure-of-a-contract.html#decorators) built in that works similarly to OpenZeppelin’s `ReentrancyGuard`.

## Summary

- Recommending `transfer()` made sense under the assumption that gas costs are constant.
- Gas costs are *not* constant. Smart contracts should be robust to this fact.
- Solidity’s `transfer()` and `send()` use a hardcoded gas amount.
- These methods should be avoided. Use `.call.value(...)("")` instead.
- This carries a risk regarding reentrancy. Be sure to use one of the robust methods available for preventing reentrancy vulnerabilities.
- Vyper’s `send()` has the same problem.

------

Thinking about smart contract security? We can provide training, ongoing advice, and smart contract auditing. [Contact us](https://diligence.consensys.io/contact/).

------

1. This is a bit of a simplification. 2300 is the amount of the *gas stipend*, which is added to the amount of gas explicitly passed to a `CALL` if the amount of ether being transferred is non-zero. Solidity’s `transfer()` sets the gas parameter to 0 if a non-zero amount of ether is transferred. When combined with the gas stipend, the result is a total of 2300 gas. If zero ether is being transferred, Solidity explicitly sets the gas parameter to 2300 so that 2300 gas is forwarded in both cases. [↩︎](https://diligence.consensys.io/blog/2019/09/stop-using-soliditys-transfer-now/#fnref:1)