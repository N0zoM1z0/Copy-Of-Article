# Project Summary

g6 offers a robust set of features covering token minting and management, liquidity pool management, trading capabilities, fee management, and reporting and monitoring. Users can initialize and manage the issuance of Jetton tokens through Jetton Minter, and use Jetton Wallet to store and transfer Jetton tokens. In terms of liquidity pool management, users can create new liquidity pools, pair Jetton tokens and TON tokens, or add liquidity to existing liquidity pools to increase the depth and trading volume of the pool, and can also move them at any time. In addition to liquidity, withdraw their Jetton tokens and TON tokens. The trading feature allows users to use TON tokens to purchase Jetton tokens, or sell Jetton tokens for TON tokens. Each transaction will charge a certain fee, which will be transferred to the designated fee collection address, while the contract will retain a certain balance for maintenance and operation. In addition, g6 also provides detailed reporting and monitoring functions. After each transaction is completed, a transaction report will be generated and sent to the specified address. Users can also query the current status of the liquidity pool at any time, including Jetton balance and TON balance.

Language: Func

Codebase: https://github.com/g6-fun/contract/commit/66f07e19acd1bd48127c42c74a726353e3b29aac

# Scope

| Filename                 | Description                                                  |
| ------------------------ | ------------------------------------------------------------ |
| g6_pool_util.fc          | Defines constants related to the Jetton pool and liquidity operations, including helper functions related to pool management and liquidity operations. |
| g6_op.fc                 | Defines identifiers for different operations, fees for various operations, functions to calculate the minimum balance and transaction fees required for different operations |
| g6_pool.fc               | Manage the Jetton pool and implement functions such as Jetton's initialization, purchase, sale, and liquidity provision. |
| g6_router.fc             | The router that manages the Jetton pool implements the startup, fund withdrawal, and pool-related reporting functions of the Jetton pool. |
| imports/jetton-wallet.fc | The dev team adds extra logic to the official jetton wallet implementation. |
| imports/jetton-minter.fc | The dev team adds extra logic to the official jetton wallet implementation. |

# Methodology

Our audit methodology comprised a comprehensive and systematic approach to uncover potential security vulnerabilities, risks, and coding issues. The key components of our methodology included:

- **Static Analysis:** We perform static analysis using our proprietary internal tools to identify potential vulnerabilities and coding issues.
- **Formal Verification:** We develop individual tests for critical functions and leverage symbolic execution tools to prove the functions in question are not vulnerable.
- **Manual Code Review**: Our engineers manually review code to identify potential vulnerabilities not captured by automatic methods.

## Engagement Summary

The engagement involved a team of skilled consultants / engineers who were responsible for various phases of the audit process, including onboarding, initial audits, additional audits, and quality assurance. Below is a summary of the engagements with specific dates and details.

| Dates                   | Engineers Engaged                | Details           |
| ----------------------- | -------------------------------- | ----------------- |
| 07/10/2024              | Hongbo Wen, Hanzhi Liu, Xi Xiong | Onboarding        |
| 07/11/2024 - 07/21/2024 | Hongbo Wen, Hanzhi Liu, Xi Xiong | Initial Audits    |
| 07/22/2024              | Hongbo Wen                       | Quality Assurance |

# Vulnerability Severity

We divide severity into four distinct levels: high, medium, low, and info. This classification helps prioritize the issues identified during the audit based on their potential impact and urgency.

- **High Severity Issues** represent critical vulnerabilities or flaws that pose a significant risk to the system's security, functionality, or performance. These issues can lead to severe consequences such as data breaches, system crashes, or major service disruptions if not addressed immediately. High severity issues typically require urgent attention and prompt remediation to mitigate potential damage and ensure the system's integrity and reliability.
- **Medium Severity Issues** are significant but not critical vulnerabilities or flaws that can impact the system's security, functionality, or performance. These issues might not pose an immediate threat but have the potential to cause considerable harm if left unaddressed over time. Addressing medium severity issues is important to maintain the overall health and efficiency of the system, though they do not require the same level of urgency as high severity issues.
- **Low Severity Issues** are minor vulnerabilities or flaws that have a limited impact on the system's security, functionality, or performance. These issues generally do not pose a significant risk and can be addressed in the regular maintenance cycle. While low severity issues are not critical, resolving them can help improve the system's overall quality and user experience by preventing the accumulation of minor problems over time.
- **Informational Severity Issues** represent informational findings that do not directly impact the system's security, functionality, or performance. These findings are typically observations or recommendations for potential improvements or optimizations. Addressing info severity issues can enhance the system's robustness and efficiency but is not necessary for the system's immediate operation or security. These issues can be considered for future development or enhancement plans.

|                                   | Number | Resolved |
| --------------------------------- | ------ | -------- |
| **High Severity Issues**          | 7      | 7        |
| **Medium Severity Issues**        | 1      | 1        |
| **Low Severity Issues**           | 3      | 3        |
| **Informational Severity Issues** | 1      | 1        |

# Disclaimer

The audit does not ensure that it has identified every security issue in the project, and it should not be seen as a confirmation that there are no more vulnerabilities. While we have conducted an analysis to the best of our ability, it is our recommendation for high-value projects to commission several independent audits, a public bug bounty program, as well as continuous onchain security auditing and monitoring. Additionally, this report should not be interpreted as personal financial advice or recommendations.

# Detailed Findings

## [HIGH] Insufficient `init_buy_done` variable

| Severity | Category           | Location   | Fix Commit                               |
| -------- | ------------------ | ---------- | ---------------------------------------- |
| **HIGH** | Insufficient Usage | g6_pool.fc | f1fe427e65418205894aca3545f3ac71db3911fb |

The `init_buy_done` variable is set to 1 too early. It will make the launcher impossible to finish the `init_buy` if the parameter filling in the `launch` is insufficient.

### Relevant Code

```
init_buy_done = 1;

int refund = 0;

if (my_balance < init_buy_min_balance(ton_amount_to_pay)) {
    ~strdump("init_buy_min_balance(ton_amount_to_pay) <= my_balance");
    ~dump(refund);
    refund = 1;
}

int jetton_amount_to_gain = ton_amount_to_pay == 0 ? 0 : buy_amount(ton_amount_to_pay);
~strdump("jetton_amount_to_gain");
~dump(jetton_amount_to_gain);
{
    int jetton_soldable = jetton_balance - jetton_amount_to_reserve;
    if (jetton_soldable < jetton_amount_to_gain) {
        jetton_amount_to_gain = jetton_soldable;
        ton_amount_to_pay = buy_amount_by_jetton(jetton_amount_to_gain);
    }
}

if ((jetton_amount_to_gain == 0) | (ton_amount_to_pay == 0)) {
    ~strdump("buy refund flag no jetton to gain");
    jetton_amount_to_gain = 0;
    ton_amount_to_pay = 0;
    refund = 1;
}
~strdump("refund");
~dump(refund);
```

### Suggested Fix

Move the `init_buy_done` variable to be after the `refund` , or add a management function to set it to 0 or 1 in the emergency case.

### Dev Response

The logic of `init_buy_done` is correct, but the dev team will add the management function.

## [HIGH] Insufficient `jetton_balance` variable

| Severity | Category   | Location   | Fix Commit                               |
| -------- | ---------- | ---------- | ---------------------------------------- |
| **HIGH** | Asset loss | g6_pool.fc | f1fe427e65418205894aca3545f3ac71db3911fb |

The `jetton_balance` variable is decreased too early.  It allows the malicious user to trigger the refund but sets the `jetton_balance` . It will lead to price manipulation vulnerability because the rate between TON and jetton token is computed based on `jetton_balance` .

### Relevant Code

```
int ton_fee = ton_amount_to_pay / 100;

jetton_balance -= jetton_amount_to_gain;

ton_balance += ton_amount_to_pay;

save_data();
```

### Suggested Fix

Move this code snippet to be after the `refund` section.

### Dev Response

Confirmed. The dev team will fix it following the suggested fix strategy.

## [HIGH] Insufficient `ton_balance` variable

| Severity | Category   | Location   | Fix Commit                               |
| -------- | ---------- | ---------- | ---------------------------------------- |
| **HIGH** | Asset loss | g6_pool.fc | f1fe427e65418205894aca3545f3ac71db3911fb |

The `ton_balance` variable is increased too early.  It allows the malicious user to trigger the refund but sets the `ton_balance` . It will lead to price manipulation vulnerability because the rate between TON and jetton token is computed based on `ton_balance` .

### Relevant Code

```
int ton_fee = ton_amount_to_pay / 100;

jetton_balance -= jetton_amount_to_gain;

ton_balance += ton_amount_to_pay;

save_data();
```

### Suggested Fix

Move this code snippet to be after the `refund` section.

### Dev Response

Confirmed. The dev team will fix it following the suggested fix strategy.

## [HIGH] Ignore all bounced messages

| Severity | Category   | Location   | Fix Commit                               |
| -------- | ---------- | ---------- | ---------------------------------------- |
| **HIGH** | Asset loss | g6_pool.fc | f1fe427e65418205894aca3545f3ac71db3911fb |

The local variable `jetton_balance` `ton_balance` has changed before sending the `transfer` message to `jetton_wallet` . if the `transfer` message fails, the pool must identify `bounced` messages to roll back `jetton_balance` and `ton_balance`.

### Relevant Code

```
() recv_internal(int my_balance, int msg_value, cell in_msg_full, slice in_msg_body) impure {
    ~strdump("pool recv_internal");

    if (in_msg_body.slice_empty?()) {
        ;; ignore all empty messages
        return ();
    }

    slice cs = in_msg_full.begin_parse();
    int flags = cs~load_uint(4);
    if (flags & 1) {
        ;; ignore all bounced messages
        return ();
    }
```

### Suggested Fix

```
;; ignore all bounced messages

-->

Check whether the sender is the corresponding jetton_wallet or ton_receiver
Check the type of bounced message 
then roll back jetton_balance and ton_balance.
```

### Dev Response

Confirmed. The dev team will fix it by adding a new manage function to sync the `jetton_balance` and `ton_balance` variables to their actual values.

## [HIGH] Transfer Ton with a wrong value

| Severity | Category   | Location   | Fix Commit                               |
| -------- | ---------- | ---------- | ---------------------------------------- |
| **HIGH** | Asset loss | g6_pool.fc | f1fe427e65418205894aca3545f3ac71db3911fb |

The Pool Contract transfer to ton_receiver with coins`my_balance - contract_maintain_balance - report_message_fee - ton_balance - ton_fee`  instead of `ton_amount_to_send` in the `sell()` method , it may cause wrong transfer value if Pool’s `my_balance` is larger or less than the expected correct value.

Before this code snippet, we assume the following equivalencies hold:

```
Equal 1:
my_balance == ton_balance{pre} + contract_maintain_balance
```

Thus, we will send ton to the seller as the following:

```
my_balance - contract_maintain_balance - report_message_fee - ton_balance{post} - ton_fee

-->

my_balance - contract_maintain_balance - report_message_fee - ton_balance{pre} + ton_fee + ton_amount_to_send - ton_fee

-->

- report_message_fee + ton_amount_to_send

-->

ton_amount_to_gain - ton_fee - report_message_fee
```

However, if `Equal 1` doesn’t hold, the seller will gain more TON coins than the expected.

### Relevant Code

```
    int ton_fee = ton_amount_to_gain / 100;
    int ton_amount_to_send = ton_amount_to_gain - ton_fee;

    jetton_balance += jetton_amount_notified;
    ton_balance -= ton_amount_to_send;
    ton_balance -= ton_fee;

    ;;transfer ton
    cell transfer_ton_message = begin_cell()
        .store_uint(0x18, 6)
        .store_slice(ton_receiver)
    ;; .store_coins(tom_amount_to_send)
        .store_coins(my_balance - contract_maintain_balance - report_message_fee - ton_balance - ton_fee)
        .store_uint(0, 1 + 4 + 4 + 64 + 32)
        .store_uint(0, 1 + 1);;no init state, body in-place
        .end_cell();
    send_raw_message(transfer_ton_message, 0);
```

### Suggested Fix

```
.store_coins(my_balance - contract_maintain_balance - report_message_fee - ton_balance - ton_fee)

-->

.store_coins(msg_value - ton_fee - report_message_fee)
```

### Dev Response

Confirmed. The dev team will fix it by leveraging the Ton intrinsic `msg_value` to compute the `refund` ton coins.

## [HIGH] Transfer wrong `add_liquidity_ton_fee`

| Severity | Category   | Location   | Fix Commit                               |
| -------- | ---------- | ---------- | ---------------------------------------- |
| **HIGH** | Asset loss | g6_pool.fc | f1fe427e65418205894aca3545f3ac71db3911fb |

If pool needs to add liquidity in method`buy` , pool shall send a `op::set_transferable` message to jetton_minter with coins `add_liquidity_ton_fee`. But  `add_liquidity_ton_fee` is the `pool` used to add liquidity in method `add_liquidity` latter. Whether the  `add_liquidity_ton_fee`  should be hold by pool instead of sending to jetton minter.

### Relevant Code

```
    if (need_add_liquidity) {

        ~strdump("buy all, prepare add liquidity");

        cell set_transferable_message = begin_cell()
            .store_uint(0x18, 6)
            .store_slice(jetton_minter_address)
            .store_coins(add_liquidity_ton_fee)
            .store_uint(0, 1 + 4 + 4 + 64 + 32)
            .store_uint(0, 1 + 1);;no state, body inplace
            .store_uint(op::set_transferable, 32)
            .store_uint(query_id, 64) ;;queryId
            .store_uint(1, 1);;set transferable to all true
            .store_uint(1, 1);;need callback
            .store_slice(sender_address)
            .end_cell();
        send_raw_message(set_transferable_message, 1);
    }
```

### Suggested Fix

```
.store_coins(add_liquidity_ton_fee)

-->
.store_coins(0)
```

### Dev Response

It is the feature. The fund will be sent back to the `add_liquidity` method.

## [HIGH] Insufficient `transferable` variable

| Severity | Category           | Location   | Fix Commit |
| -------- | ------------------ | ---------- | ---------- |
| **HIGH** | Insufficient Usage | g6_pool.fc | -          |

The pool sends a `op::set_transferable` message to `jetton_minter` to set `transferable=1` if the pool’s `jetton_soldable=0` and needs to add liquidity after transfer with jetton_wallet_pool in the method `buy`. But if the transfer fails, the pool should roll back the `jetton_balance` and `ton_balance`, and also need to roll back transferable status with `transferable=0` and `graduated=0`. Besides this impact, the status of `graduated=1`  will also affect the pool's ability to process the message of `op::buy`  ***\*in the future\**.**

### Relevant Code

```
if (op == op::buy) {
        ~strdump("op::buy");
        check_graduate();
        check_init_buy_done();
        buy(sender_address, my_balance, msg_value, in_msg_body);
        return ();
}
```

### Suggested Fix

Add the roll back logic to set the `transferable=0` and `graduated=0` .

### Dev Response

The dev team will use the manual manager function to roll back the `transferable` and `graduated`. Also, add a state-machine to manage those variables.

## [MEDIUM] Insufficient `graduated` variable

| Severity   | Category           | Location   | Fix Commit                               |
| ---------- | ------------------ | ---------- | ---------------------------------------- |
| **MEDIUM** | Insufficient Usage | g6_pool.fc | f1fe427e65418205894aca3545f3ac71db3911fb |

The `graduated` variable could never be set to 0 again after it is set to 1. This will make a stuck if there is an emergency case.

### Relevant Code

```
graduated = 1;
```

### Suggested Fix

Add a management function to change the `graduated` variable.

### Dev Response

Confirmed. The dev team will fix it following the suggested fix strategy.

## [LOW] Indistinguishable address computation

| Severity | Category           | Location   | Fix Commit                               |
| -------- | ------------------ | ---------- | ---------------------------------------- |
| **LOW**  | Insufficient Usage | g6_pool.fc | f1fe427e65418205894aca3545f3ac71db3911fb |

The computation of the contract address is indistinguishable, preventing the user from deploying two different pools by default. Also, the launch pool can’t be distinguished by crossing frontend.

### Relevant Code

```
cell pool_state_init = calculate_pool_state_init(
    my_address(),
    jetton_wallet_code,
    jetton_minter_code,
    pool_code,
    jetton_content,
    ston_fi_router_address,
    ston_fi_jetton_pton_address,
    fee_collector_address
);
```

### Suggested Fix

Add a unique identification to distinguish the launch pools using the same jetton content.

```
cell pool_state_init = calculate_pool_state_init(
		**pool_id,**
    my_address(),
    jetton_wallet_code,
    jetton_minter_code,
    pool_code,
    jetton_content,
    ston_fi_router_address,
    ston_fi_jetton_pton_address,
    fee_collector_address
);
```

### Dev Response

Confirmed. The dev team will fix it following the suggested fix strategy.

## [LOW] Missing `jetton_soldable` get method

| Severity | Category              | Location   | Fix Commit |
| -------- | --------------------- | ---------- | ---------- |
| **LOW**  | Missing Functionality | g6_pool.fc | N.A.       |

The local variable `jetton_soldable` is useful for the user to compute the proper `slippage_in_percent` . Otherwise, the user can’t call the buy or sell if the amount is large.

### Relevant Code

```
{

    int jetton_soldable = jetton_balance - jetton_amount_to_reserve;
    int delta = expected_jetton_soldable_amount < jetton_soldable ?
    jetton_soldable - expected_jetton_soldable_amount :
    expected_jetton_soldable_amount - jetton_soldable;

    ;;delta / jetton_soldable > slippage_in_percent / 100
    if (delta * 100 > slippage_in_percent * jetton_soldable) {
        ~strdump("refund: buy refund flag slippage");
        refund_flag = 1;
    }
}
```

### Suggested Fix

Add a method_id function to export the `jetton_soldable` variable.

### Dev Response

`get_pool_data` works as the same functionality.

## [LOW] Redundant code

| Severity | Category       | Location         | Fix Commit                               |
| -------- | -------------- | ---------------- | ---------------------------------------- |
| **LOW**  | Redundant Code | Jetton-wallet.fc | f1fe427e65418205894aca3545f3ac71db3911fb |

The following code in the method `receive_tokens_cb` did not find any relevant calls, Please confirm if there are any scenarios for use.

### Relevant Code

```
if (forward_ton_amount) {

        ~strdump("jetton wallet receive_tokens_cb: into forward_ton_amount if");

        msg_value -= (forward_ton_amount + fwd_fee);
        slice either_forward_payload = in_msg_body;

        var msg_body = begin_cell()
            .store_uint(op::transfer_notification(), 32)
            .store_uint(query_id, 64)
            .store_coins(jetton_amount)
            .store_slice(from_address)
            .store_slice(either_forward_payload)
            .end_cell();

        var msg = begin_cell()
            .store_uint(0x10, 6) ;; we should not bounce here cause receiver can have uninitialized contract
            .store_slice(owner_address)
            .store_coins(forward_ton_amount)
            .store_uint(1, 1 + 4 + 4 + 64 + 32 + 1 + 1)
            .store_ref(msg_body);

        send_raw_message(msg.end_cell(), 1);
    }

    if ((response_address.preload_uint(2) != 0) & (msg_value > 0)) {

        ~strdump("jetton wallet receive_tokens_cb: into response_address if");
        var msg = begin_cell()
            .store_uint(0x10, 6) ;; nobounce - int_msg_info$0 ihr_disabled:Bool bounce:Bool bounced:Bool src:MsgAddress -> 010000
            .store_slice(response_address)
            .store_coins(msg_value)
            .store_uint(0, 1 + 4 + 4 + 64 + 32 + 1 + 1)
            .store_uint(op::excesses(), 32)
            .store_uint(query_id, 64);
        send_raw_message(msg.end_cell(), 2);
    }
```

### Suggested Fix

Check the control flow to confirm whether this code snippet could be executed.

### Dev Response

The logic could be executed when two users trade.

## [INFO] Cell Optimization

| Severity | Category           | Location     | Fix Commit |
| -------- | ------------------ | ------------ | ---------- |
| **INFO** | Insufficient Usage | g6_router.fc | N.A.       |

The two `store_uint` statements could be merged into one statement.

### Relevant Code

```
;;return all balance to launcher
cell take_message = begin_cell()
    .store_uint(0x18, 6)
    .store_slice(sender_address)
    .store_coins(ton_to_take)
    .store_uint(0, 1 + 4 + 4 + 64 + 32)
    .store_uint(0 + 0, 1 + 1) ;;no pay load
    .end_cell();
```

### Dev Response

The dev team will keep the style.