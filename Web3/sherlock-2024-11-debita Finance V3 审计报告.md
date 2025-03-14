# 一

## Summary

There is no verification of the incentives recipient, which allows anyone to impersonate other borrowers and claim their incentives.

## Root Cause

Vulnerable code:

2024-11-debita-finance-v3-HeYuan-33/Debita-V3-Contracts/contracts/DebitaIncentives.sol

Line 203 in 1465ba6

IERC20(token).transfer(msg.sender, amountToClaim);

Using msg.sender to send rewards to the caller without performing a check allows an attacker to impersonate a borrower and claim their incentives . Additionally, we can see that the function claimIncentives：
2024-11-debita-finance-v3-HeYuan-33/Debita-V3-Contracts/contracts/DebitaIncentives.sol

Lines 142 to 147 in 1465ba6

```
function claimIncentives( 
    address[] memory principles, 
    address[][] memory tokensIncentives, 
    uint epoch 
) public { 
    // get information 
```

As long as the attacker forwards another person’s parameter information, they can impersonate them and claim the incentives
Internal pre-conditions
The claimIncentives function is public

## External pre-conditions

No response

## Attack Path

- Alice has successfully borrowed tokens, and when she calls the claimIncentives function to claim the incentives, the transaction is packaged into the transaction pool.
- Bob is always ready to monitor this transaction pool. Upon discovering Alice’s transaction, he can retrieve the transaction details (address[] memory principles, address[][] memory tokensIncentives, uint epoch), and then submit a higher gas fee for the same transaction, which will be processed first.
- At this point, Bob impersonates Alice to claim her incentives. When Alice’s transaction is processed, she will be marked as having already claimed the incentives

## Impact

Borrowers are unable to claim the rewards they are entitled to.
A front-running transaction attack occurs.

## PoC

No response

## Mitigation

Perform a check on the msg.sender calling the claimIncentives function.

```
function claimIncentives(
    address[] memory principles,
    address[][] memory tokensIncentives,
    uint epoch,
) public {
    // Ensure the caller is the borrower
    require(msg.sender == borrower, "Only the borrower can claim incentives");

    // ... existing logic
}
```

Ensure that this epoch ,the principal, and the borrower are correctly matched.

# 二

## Summary

We all know that using transferFrom to send tokens lacks the security of using safeTransferFrom.

## Root Cause

Vulnerable code:

2024-11-debita-finance-v3-HeYuan-33/Debita-V3-Contracts/contracts/DebitaIncentives.sol

Lines 269 to 274 in 1465ba6

```
IERC20(incentivizeToken).transferFrom( 
    msg.sender, 
    address(this), 
    amount 
); 

require(amount > 0, "Amount must be greater than 0"); 
```

We can see that using transferFrom to transfer tokens to a contract is somewhat unsafe. Additionally, the operation of checking whether the amount is zero after the transfer is a bit redundant.
If it returns a bool value to determine whether the transfer was successful, then the vulnerability in the code is that it doesn’t check whether transferFrom actually succeeded.

## Internal pre-conditions

No response

## External pre-conditions

No response

## Attack Path

No response

## Impact

Using transferFrom to transfer tokens is less secure than safeTransferFrom.
We cannot be sure if transferFrom successfully completed the transfer.
Checking if the amount is zero after the transfer is performed in the wrong order.

## PoC

No response

## Mitigation

Use the more secure safeTransferFrom for the token transfer.
Change the order of the check for whether the amount is zero.

```
       // transfer the tokens
      // IERC20(incentivizeToken).transferFrom(
    //     msg.sender,
   //    address(this),
  //     amount
 //  );
//   require(amount > 0, "Amount must be greater than 0");
     
     require(amount > 0, "Amount must be greater than 0");
     SafeERC20.safeTransferFrom(
           IERC20(incentivizeToken),
         msg.sender,
         address(this),
         amount
     );
```

# 三

## Summary

In the addFunds function of the DebitaLendOffer-Implementation contract, there is no check on theamountbeing added.

## Root Cause

Valnerable code:

2024-11-debita-finance-v3-HeYuan-33/Debita-V3-Contracts/contracts/DebitaLendOffer-Implementation.sol

Lines 168 to 173 in 1465ba6

```
SafeERC20.safeTransferFrom( 
    IERC20(lendInformation.principle), 
    msg.sender, 
    address(this), 
    amount 
); 
```

As we can see, there is no check on the amount before the transfer, which allows the lender or owner to transfer zero tokens, wasting gas.

## Internal pre-conditions

No response

## External pre-conditions

No response

## Attack Path

If an attacker becomes a lender, they can repeatedly call the addFunds function, adding a large number of zero amounts to the DebitaLendOffer-Implementation contract, which prevents other lenders from adding their loan amounts.

## Impact

An attacker sends a large number of requests with a zero amount to the DebitaLendOffer-Implementation contract, consuming a lot of gas, which prevents legitimate lenders from adding loan amounts.
The DebitaLendOffer-Implementation contract will receive a large number of requests with a zero amount.

## PoC

No response

## Mitigation

Add a check to ensure the amount is not zero, as follows:

```
require(amount > 0, "Amount must be greater than zero");
SafeERC20.safeTransferFrom(
       IERC20(lendInformation.principle),
       msg.sender,
       address(this),
       amount
   );
```

# 四

## Summary

Although the claimInterest function in the DebitaV3Loan.sol contract is marked as internal, there is still no check for the lender.

## Root Cause

Valnerable code:

2024-11-debita-finance-v3-HeYuan-33/Debita-V3-Contracts/contracts/DebitaV3Loan.sol

Lines 259 to 269 in 1465ba6

```
function claimInterest(uint index) internal { 
    IOwnerships ownershipContract = IOwnerships(s_OwnershipContract); 
    infoOfOffers memory offer = loanData._acceptedOffers[index]; 
    uint interest = offer.interestToClaim; 
 
    require(interest > 0, "No interest to claim"); 
 
    loanData._acceptedOffers[index].interestToClaim = 0; 
    SafeERC20.safeTransfer(IERC20(offer.principle), msg.sender, interest); 
    Aggregator(AggregatorContract).emitLoanUpdated(address(this)); 
} 
```

As we can see from above, there is no check for the lender, which could lead to the interest being incorrectly claimed.
By comparing it with the function that has the same functionality, we can see that:
2024-11-debita-finance-v3-HeYuan-33/Debita-V3-Contracts/contracts/DebitaV3Loan.sol

Lines 288 to 311 in 1465ba6

```
function _claimDebt(uint index) internal { 
    LoanData memory m_loan = loanData; 
    IOwnerships ownershipContract = IOwnerships(s_OwnershipContract); 
 
    infoOfOffers memory offer = m_loan._acceptedOffers[index]; 
    require( 
        ownershipContract.ownerOf(offer.lenderID) == msg.sender, 
        "Not lender" 
    ); 
    require(offer.paid == true, "Not paid"); 
    require(offer.debtClaimed == false, "Already claimed"); 
    loanData._acceptedOffers[index].debtClaimed = true; 
    ownershipContract.burn(offer.lenderID); 
    uint interest = offer.interestToClaim; 
    offer.interestToClaim = 0; 
 
    SafeERC20.safeTransfer( 
        IERC20(offer.principle), 
        msg.sender, 
        interest + offer.principleAmount 
    ); 
 
    Aggregator(AggregatorContract).emitLoanUpdated(address(this)); 
} 
```

There still needs to be a check for the lender, as this would also serve as an additional layer of protection.

## Internal pre-conditions

No response

## External pre-conditions

No response

## Attack Path

No response

## Impact

This could lead to the interest being incorrectly claimed.

## PoC

No response

## Mitigation

Add a check for the lender, as follows:

```
function claimInterest(uint index) internal {
       IOwnerships ownershipContract = IOwnerships(s_OwnershipContract);
       infoOfOffers memory offer = loanData._acceptedOffers[index];
       uint interest = offer.interestToClaim;

         require(
           ownershipContract.ownerOf(offer.lenderID) == msg.sender,
           "Not lender"
       );

       require(interest > 0, "No interest to claim");

       loanData._acceptedOffers[index].interestToClaim = 0;
       SafeERC20.safeTransfer(IERC20(offer.principle), msg.sender, interest);
       Aggregator(AggregatorContract).emitLoanUpdated(address(this));
   }
```

# 五

## Summary

In the payDebt function of the DebitaV3Loan.sol contract, after calculating the interest, the safe transfer does not ensure that the address receiving the interest is not the zero address.

## Root Cause

Vulnerable code:

2024-11-debita-finance-v3-HeYuan-33/Debita-V3-Contracts/contracts/DebitaV3Loan.sol

Lines 243 to 248 in 1465ba6

```
SafeERC20.safeTransferFrom( 
    IERC20(offer.principle), 
    msg.sender, 
    feeAddress, 
    feeOnInterest 
); 
```

As we can see from above, the safe transfer function of ERC20 is used, but it cannot ensure that feeOnInterest is not transferred to the zero address, resulting in irretrievable loss.

## Internal pre-conditions

## External pre-conditions

## Attack Path

No response

## Impact

The DebitaV3Loan.sol contract will lose the earned interest, which is a very unfortunate situation.

## PoC

No response

## Mitigation

Perform a zero address check on feeAddress as follows:

```
// Check if feeAddress is the zero address
  require(feeAddress != address(0), "Invalid fee address: zero address");

SafeERC20.safeTransferFrom(
    IERC20(offer.principle),
    msg.sender,
    feeAddress,
    feeOnInterest
);\
```

# 六

## Summary

2024-11-debita-finance-v3-HeYuan-33/Debita-V3-Contracts/contracts/DebitaBorrowOffer-Factory.sol

Lines 143 to 144 in 8d0c8c0

```
uint balance = IERC20(_collateral).balanceOf(address(borrowOffer)); 
require(balance >= _collateralAmount, "Invalid balance"); 
```

In thecontract, it checks whether the balance of an IERC20 token has successfully met the required amount, but it does not check the balance of an IERC721 token. If the user uses an IERC721 token as collateral, this check will fail, and it is also uncertain whether the IERC721 token has successfully entered the contract.DebitaBorrowOffer-Factory.sol
Root Cause
It only checks if the collateral staked by the user is an IERC20 token, and confirms whether the DebitaBorrowOffer-Factory.sol contract has enough IERC20 tokens.
This is an incorrect check, as if _collateral is an IERC721 token, this check will cause the contract to fail.

## Internal pre-conditions

No response

## External pre-conditions

No response

## Attack Path

## Impact

An attacker could use an IERC721 token as collateral. When the attacker takes out a loan and deposits the IERC721 token as collateral, it will cause the transaction to fail. If the attacker repeatedly executes the same transaction, it could potentially cause the contract to become unresponsive.

A legitimate user attempting to use an IERC721 token as collateral for a loan will also encounter an error, preventing the transaction from being processed, which would break the functionality of the contract.

An attacker can use an IERC721 token as collateral without successfully transferring it to the contract, effectively enabling them to borrow funds without providing any actual collateral.

## PoC

No response

## Mitigation

To enhance the contract’s validation functionality, it should not only check if the IERC20 collateral has been successfully deposited into the DebitaBorrowOffer-Factory.sol contract, but also account for the case where the collateral is an IERC721 token. Below is the suggested modified code:

```
if (_isNFT) {
    address nftOwner = IERC721(_collateral).ownerOf(_receiptID);
    require(nftOwner == address(borrowOffer), "NFT not transferred correctly");
} else {
    uint balance = IERC20(_collateral).balanceOf(address(borrowOffer));
    require(balance >= _collateralAmount, "Invalid balance");
}
```

# 

感觉还是很难。就是发现不了他们的错误。这个合约的逻辑很缜密，所以只有等正确的审计报告出来，然后再多学习学习

## 这次的审计，有让我学会一些东西，在函数中定义重复owner,会导致改变的量状态不同，比如这次的合约中，就错误的使用了owner;

```
function changeOwner(address owner) public {
      require(msg.sender == owner, "Only owner");
      require(deployedTime + 6 hours > block.timestamp, "6 hours passed");
      owner = owner;
  }
```

当你像改变合约的owner时，由于传递的参数和合约的状态变量owner一样，所以就是自己赋值
这里的 owner 参数与状态变量 owner 同名，这就导致了一个作用域的问题。
在 Solidity 中，函数参数的作用域优先于状态变量，这意味着在函数内部，owner 会首先指代函数的参数 address owner，而不是合约的状态变量 owner。
因此，owner = owner; 只是将函数的参数 owner 赋值给它自己，并没有对链上的状态变量 owner 做任何修改。
详细解释
函数参数优先级： 当你在函数中定义一个与状态变量同名的参数时，函数会优先使用该参数，而不是状态变量。也就是说，在函数内部，owner 这个名字指代的是参数 address owner，而不是链上的状态变量。
赋值的行为：
owner = owner; 这行代码看似是给状态变量 owner 赋值，但实际上它只是给函数参数 owner 赋值。由于函数参数和状态变量是不同的存储位置，这行代码并没有实际改变链上的状态变量。
在 Solidity 中，owner = owner; 是一个 自我赋值，没有任何效果，除非你在这个赋值中显式地引用状态变量。

> 状态变量（State Variables）：状态变量存储在区块链上，生命周期与合约相同，可以在整个合约中访问和修改。
> 函数参数（Function Arguments）：这些变量仅在函数执行期间有效，当函数执行完后，它们就不再存在。
> 局部变量（Local Variables）：在函数内部声明的变量，它们只在函数的执行期间有效。

## 可以通过执行存款，阻止借贷订单的取消

```
function addFunds(uint amount) public nonReentrant {  
       require(  
           msg.sender == lendInformation.owner ||  
               IAggregator(aggregatorContract).isSenderALoan(msg.sender),  
           "Only owner or loan"  
       );  
       SafeERC20.safeTransferFrom(  
           IERC20(lendInformation.principle),  
           msg.sender,  
           address(this),  
           amount  
       );  
       lendInformation.availableAmount += amount;  
       IDLOFactory(factoryContract).emitUpdate(address(this));  
   }  
function cancelOffer() public onlyOwner nonReentrant {  
        uint availableAmount = lendInformation.availableAmount;  
        lendInformation.perpetual = false;  
        lendInformation.availableAmount = 0;  
@>        require(availableAmount > 0, "No funds to cancel");  
        isActive = false;  
  
        SafeERC20.safeTransfer(  
            IERC20(lendInformation.principle),  
            msg.sender,  
            availableAmount  
        );  
        IDLOFactory(factoryContract).emitDelete(address(this));  
@>        IDLOFactory(factoryContract).deleteOrder(address(this));  
        // emit canceled event on factory  
    }  
  function deleteOrder(address _lendOrder) external onlyLendOrder {  
        uint index = LendOrderIndex[_lendOrder];  
        LendOrderIndex[_lendOrder] = 0;  
  
        // switch index of the last borrow order to the deleted borrow order  
        allActiveLendOrders[index] = allActiveLendOrders[activeOrdersCount - 1];  
        LendOrderIndex[allActiveLendOrders[activeOrdersCount - 1]] = index;  
  
        // take out last borrow order  
  
        allActiveLendOrders[activeOrdersCount - 1] = address(0);  
  
@>        activeOrdersCount--;  
    }  
```

攻击者可以利用 addFunds 函数中缺失的活跃订单检查，向一个 非活跃的借贷订单 中添加资金。这样，攻击者可以通过以下步骤触发攻击：

攻击者创建一个借贷订单，并通过 DLOFactory::activeOrdersCount 增加活跃订单计数。
攻击者调用 cancelOffer 函数取消该借贷订单，并调用 deleteOrder 减少活跃订单计数。
然后，攻击者向该已取消的借贷订单中添加资金，成功绕过了 cancelOffer 中的检查，允许 addFunds 通过。
攻击者继续调用 cancelOffer，进一步将活跃订单计数减少。
最终，攻击者将 DLOFactory::activeOrdersCount 计数降为 0。
当 activeOrdersCount 为零时，后续调用 deleteOrder 或相关函数将因为算术下溢（underflow）而失败，导致后续功能无法正常执行。
根本原因
问题出在 DLOImplementation::addFunds 函数中，它没有检查订单是否处于活跃状态。正常情况下，只有活跃订单才能向其中添加资金。但是，由于缺少这一检查，攻击者可以向一个已经取消的订单中添加资金，从而绕过订单取消的逻辑。
这个漏洞就是需要结合逻辑一起看，看它的检查条件，能不能绕过然后发生攻击，这次主要看合约的实现漏洞了，没有发现逻辑上可以绕过的点

## 没有统一单位（10^18,10^8）往往会出现计算错误

## 下溢的问题

好遗憾，最开始的时候还注意了这个地方，但是想到solidity 8.0 之后会检查溢出的，就没有太注意，但是其实是有一个报错返回的，那么就可以使DOS攻击

```
uint256 alreadyUsedTime = block.timestamp - loanStartedAt;
uint256 extendedTime = maxDeadline - alreadyUsedTime - block.timestamp;
alreadyUsedTime = currentTime - loanStartedAt = 1705190400 - 1704067200 = 1,123,200（大约13天）
extendedTime = maxDeadline - alreadyUsedTime - currentTime = 1705276800 - 1,123,200 - 1705190400
             = 1705276800 - 1706313600
             = -1,036,800
```

这个 extendedTime 变量并没有被实际使用，但它会影响合约中的计算，导致算术下溢错误。在某些情况下，借款人即使满足所有其他扩展条件，仍然无法扩展贷款。
其实就是就是影响了用户的体验

## 跳过白名单，直接阻断了后续的领取代币

这个函数也是我反复看的，但是差点，没有发现如果直接return的话，那么就会导致后面满足白名单的人不能够领取奖励，又是一个遗憾

```
function updateFunds(  
    infoOfOffers[] memory informationOffers,  
    address collateral,  
    address[] memory lenders,  
    address borrower  
) public onlyAggregator {  
    for (uint i = 0; i < lenders.length; i++) {  
        bool validPair = isPairWhitelisted[informationOffers[i].principle][  
            collateral  
        ];  
        if (!validPair) {  
            return;  // 这里的return导致函数提前退出，跳过后续有效的配对
        }  
        address principle = informationOffers[i].principle;  
        uint _currentEpoch = currentEpoch();  
        lentAmountPerUserPerEpoch[lenders[i]][  
            hashVariables(principle, _currentEpoch)  
        ] += informationOffers[i].principleAmount;  
        totalUsedTokenPerEpoch[principle][  
            _currentEpoch  
        ] += informationOffers[i].principleAmount;  
        borrowAmountPerEpoch[borrower][  
            hashVariables(principle, _currentEpoch)  
        ] += informationOffers[i].principleAmount;  
        emit UpdatedFunds(  
            lenders[i],  
            principle,  
            collateral,  
            borrower,  
            _currentEpoch  
        );  
    }  
}
```

## FOT代币，在转账的时候会产生手续费，就会导致一些计算失败

在 TaxTokensReceipt 合约中，存在一个问题，导致 Fee-on-Transfer (FOT) 代币在存款时出现交易回滚。问题的根本原因是合约假设用户存入的代币数量与转账的实际数量相同，但对于 Fee-on-Transfer 代币，转账过程中会扣除一定的费用。因此，合约在检查代币差额时，总是期望接收到与用户指定数量相等的金额，但实际收到的数量较少，导致存款失败。
Fee-on-Transfer (FOT) 代币：这类代币在每次转账时会自动扣除一定比例的费用，导致转账到合约的实际金额（difference）少于用户指定的存款金额（amount）。
问题发生的位置：在 TaxTokensReceipt.sol 合约的 deposit() 函数中，合约将转账前后的余额差（difference）与用户指定的 amount 进行比较，假设两者应当相等。然而，由于 FOT 代币的费用机制，实际转账的金额始终少于用户指定的 amount，因此 difference >= amount 检查始终失败，导致交易回滚。

又是一个新的知识，FOT代币，会有手续费

## 预言机没有检查时间过时，导致价格更新不一致

DebitaChainlink.sol 合约中的 getThePrice() 函数对 Chainlink 价格预言机的数据进行验证时，存在验证不完整的问题。虽然函数进行了一些基本的检查（如合约是否暂停、价格预言机是否存在、L2序列器是否正常等），但它缺少对价格更新时间戳、回合完整性以及回合排序的验证。这意味着，即使价格预言机的数据已经过时（但价格仍大于零），合约仍然会接受这些数据，可能导致使用陈旧或无效的价格。

根本原因：
getThePrice() 函数目前只验证了以下几点：

合约是否暂停（isPaused）。
价格预言机是否存在。
L2序列器是否正常（对于L2链）。
返回的价格是否大于零。
然而，它没有验证：

价格更新的时间戳（updatedAt）。
回合是否完整（answeredInRound）。
回合是否按顺序回答（answeredInRound >= roundId）。
合约中的 getThePrice() 函数从 Chainlink 价格预言机获取最新价格数据时，验证逻辑如下：

```
(, int price, , , ) = priceFeed.latestRoundData();  
require(isFeedAvailable[_priceFeed], "Price feed not available");  
require(price > 0, "Invalid price");  
```

但没有进一步验证价格是否来自一个有效的回合，或者回合是否完整。也没有检查 updatedAt 时间戳，可能导致使用陈旧的价格数据。具体来说，以下情况未被考虑：

时间戳验证缺失： 如果预言机数据的更新时间戳很久之前，那么这个价格数据就是“过时”的，应该拒绝使用。
回合完整性检查： 如果价格数据属于一个不完整的回合（例如，数据没有完全更新），则无法保证其准确性。
回合顺序验证： 需要确保返回的回合数据是按顺序的，否则有可能是过时的无效数据。

使用预言机的话，就要注意到这几个细节
配置更新时间阈值： 为了应对不同的市场环境，可以让合约所有者设置一个自定义的价格数据有效时间（比如，10分钟或者更短）。
价格验证事件： 在每次价格验证时，触发事件记录价格数据的验证状态，这有助于监控和审计价格来源的健康状态。
公开数据接口： 提供一个视图函数，返回包括时间戳和回合 ID 在内的完整价格数据，供外部用户验证和分析。
时间戳验证缺失： 如果预言机数据的更新时间戳很久之前，那么这个价格数据就是“过时”的，应该拒绝使用。
回合完整性检查： 如果价格数据属于一个不完整的回合（例如，数据没有完全更新），则无法保证其准确性。
回合顺序验证： 需要确保返回的回合数据是按顺序的，否则有可能是过时的无效数据。