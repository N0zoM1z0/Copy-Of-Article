## Intro[¶](https://neodyme.io/en/blog/solana_common_pitfalls/#intro)

Hey everyone!

We’re Neodyme, a team of security researchers who have spent the past ~12 months inspecting the internals of the Solana blockchain. Over the course of our research, we discovered and reported several vulnerabilities in the Solana core code, ultimately helping to secure the chain against attackers.

A few months ago, we were sponsored by the Solana Foundation to also set up a peer review system for smart contracts that are important for the Solana ecosystem. Since then, we’ve been working with developers from a range of projects building on Solana to assist them in securing their contracts. We’ve audited dozens of contracts, using our unique experience with Solana to uncover many exploitable bugs. During these audits, we’ve discovered intricate vulnerabilities in some of the major projects on the chain, and our reviews helped prevent the potential theft of roughly USD 1 billion worth of assets.

However, as Solana is such a rapidly growing ecosystem, we have nowhere near enough capacity to manually audit every new contract to our standards. Instead, we’ll be sharing some of the knowledge we’ve built over the course of our many audits in this blog, in hopes that developers and other auditors will be able to make use of it.

In this post, we want to raise awareness about the five most common vulnerabilities in Solana contracts that we keep finding during our audits. We’ll keep the vulnerability descriptions short and concise and provide a simplified example as well as a TL;DR for each vulnerability so that you can easily reference them while coding.

Let’s get into it!

## Pitfalls[¶](https://neodyme.io/en/blog/solana_common_pitfalls/#pitfalls)

### Missing ownership check[¶](https://neodyme.io/en/blog/solana_common_pitfalls/#missing-ownership-check)

#### TL;DR[¶](https://neodyme.io/en/blog/solana_common_pitfalls/#tldr)

**Always** (!) check the `AccountInfo::owner` field of accounts that aren’t supposed to be fully user-controlled. Ideally, you’d create a helper function that takes an untrusted `AccountInfo`, checks the owner and returns an object of a different, trusted type. Your contract should only trust accounts owned by itself.

#### Description[¶](https://neodyme.io/en/blog/solana_common_pitfalls/#description)

Solana accounts have an `owner` field:

```
pub struct AccountInfo<'a> {
    // [...]

    /// Program that owns this account
    pub owner: &'a Pubkey,
    
    // [...]
}
```

It holds the pubkey of the only entity allowed to write to that account’s data. An account owned by anyone other than the party you expect it to be owned by could potentially contain malicious data and therefore cannot be trusted.

#### Example[¶](https://neodyme.io/en/blog/solana_common_pitfalls/#example)

Consider the following code defining an instruction `withdraw_token_restricted`. The intention of the developer was that this is an admin-only instruction to withdraw funds from the contract vault.

```
fn withdraw_token_restricted(program_id: &Pubkey, accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let vault = next_account_info(account_iter)?;
    let admin = next_account_info(account_iter)?;
    let config = ConfigAccount::unpack(next_account_info(account_iter)?)?;
    let vault_authority = next_account_info(account_iter)?;
    
    
    if config.admin != admin.pubkey() {
        return Err(ProgramError::InvalidAdminAccount);
    }
    
    // ...
    // Transfer funds from vault to admin using vault_authority
    // ...
    
    Ok(())
}
```

The function uses an account called `config` (which it assumes to contain trusted data) to store the admin pubkey and hence ensure that only the admin account can use this instruction.

Since the smart contract does not check that `config` is owned by the correct entity, an attacker can supply a maliciously crafted `config` account with an arbitrary `admin` field. Now if the smart contract tries to verify that the given admin account is indeed the admin account stored in its `config` account, it will be fooled by the malicious `config`. The contract will then happily withdraw funds to the attacker-controlled `admin` account.

To fix this, we simply need to insert the missing ownership check:

```
fn withdraw_token_restricted(program_id: &Pubkey, accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let vault = next_account_info(account_iter)?;
    let admin = next_account_info(account_iter)?;
    let config = ConfigAccount::unpack(next_account_info(account_iter)?)?;
    let vault_authority = next_account_info(account_iter)?;
    
    
    if config.owner != program_id {
        return Err(ProgramError::InvalidConfigAccount);
    }
    
    if config.admin != admin.pubkey() {
        return Err(ProgramError::InvalidAdminAccount);
    }
    
    // ...
    // Transfer funds from vault to admin using vault_authority
    // ...
    
    Ok(())
}
```

This ensures that the `config` account can only be modified by the contract itself and hence that it contains valid data.

An even better fix than the above is to introduce a different type for accounts that have already been verified to be program-owned and to then ensure that the contract does any relevant computations only with accounts of that type.

### Missing signer check[¶](https://neodyme.io/en/blog/solana_common_pitfalls/#missing-signer-check)

#### TL;DR[¶](https://neodyme.io/en/blog/solana_common_pitfalls/#tldr-1)

If an instruction should only be available to a restricted set of entities, you need to verify that the call has been signed by the appropriate entity by checking the `AccountInfo::is_signer` field.

#### Description[¶](https://neodyme.io/en/blog/solana_common_pitfalls/#description-1)

Almost any smart contract has instructions that should only be called by certain entities — be it for admin-only instructions like locking the contract, or for user-specific instructions that modify the state of a user’s account. Even though it should be common sense to always verify that the respective entity has signed the corresponding transaction, these checks are often forgotten.

#### Example[¶](https://neodyme.io/en/blog/solana_common_pitfalls/#example-1)

```
fn update_admin(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let config = ConfigAccount::unpack(next_account_info(account_iter)?)?;
    let admin = next_account_info(account_iter)?;
    let new_admin = next_account_info(account_iter)?;

    // ...
    // Validate the config account...
    // ...
    
    if admin.pubkey() != config.admin {
        return Err(ProgramError::InvalidAdminAccount);
    }
    
    config.admin = new_admin.pubkey();
    
    Ok(())
}
```

This instruction updates the contract admin. It attempts to ensure that the instruction is only callable by the current `admin` by comparing the `admin` account to the one in the current `config` account. However, there is no check to verify that the current admin has actually signed this operation. Users can supply arbitrary accounts when invoking an instruction, so there’s nothing stopping an attacker from just supplying the current admin as `admin` and their own account as `new_admin`. The instruction will replace the current admin with the new, malicious one, potentially giving the attacker full control over the contract.

We can fix this by inserting the missing check:

```
fn update_admin(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let config = ConfigAccount::unpack(next_account_info(account_iter)?)?;
    let admin = next_account_info(account_iter)?;
    let new_admin = next_account_info(account_iter)?;

    // ...
    // Validate the config account...
    // ...
    
    if admin.pubkey() != config.admin {
        return Err(ProgramError::InvalidAdminAccount);
    }
    
    // check that the current admin has signed this operation
    if !admin.is_signer {
        return Err(ProgramError::MissingSigner);
    }
    
    config.admin = new_admin.pubkey();
    
    Ok(())
}
```

### Integer overflow & underflow[¶](https://neodyme.io/en/blog/solana_common_pitfalls/#integer-overflow--underflow)

#### TL;DR[¶](https://neodyme.io/en/blog/solana_common_pitfalls/#tldr-2)

Use [checked math](https://doc.rust-lang.org/book/ch03-02-data-types.html#integer-overflow) and [checked casts](https://doc.rust-lang.org/std/convert/trait.TryFrom.html) whenever possible to avoid unintentional and possibly malicious behaviour.

#### Description[¶](https://neodyme.io/en/blog/solana_common_pitfalls/#description-2)

It’s a common error to think that Rust catches overflows, when in fact this is only true in debug mode. Rust integers have fixed sizes and can only represent values within their supported ranges. If an arithmetic operation results in a higher or lower value, the value will wrap around with two’s complement. Citing from the [Rust documentation](https://doc.rust-lang.org/book/ch03-02-data-types.html#integer-overflow):

> When you’re compiling in release mode with the `--release` flag, Rust does not include checks for integer overflow that cause panics. Instead, if overflow occurs, Rust performs two’s complement wrapping. In short, values greater than the maximum value the type can hold “wrap around” to the minimum of the values the type can hold. In the case of a `u8`, 256 becomes 0, 257 becomes 1, and so on. The program won’t panic, but the variable will have a value that probably isn’t what you were expecting it to have.

Note that when using the Solana BPF toolchain (`$ cargo build-bpf`), you’re compiling in release mode.

#### Example[¶](https://neodyme.io/en/blog/solana_common_pitfalls/#example-2)

Have look at the following piece of code for a `withdraw_token` instruction:

```
let FEE: u32 = 1000; 

fn withdraw_token(program_id: &Pubkey, accounts: &[AccountInfo], amount: u32) -> ProgramResult {

    // ...
    // deserialize & validate user and vault accounts
    // ...
    
    if amount + FEE > vault.user_balance[user_id] {
        return Err(ProgramError::AttemptToWithdrawTooMuch);
    }
    
    // ...
    // Transfer `amount` many tokens from vault to user-controlled account ...
    // ...
    
    Ok(())
}
```

The code attempts to ensure a user can’t withdraw more than their previously deposited balance, minus a fee from the vault.

Let’s say an attacker deposits `100,000` tokens. This will set `vault.user_balance[user_id]` to `100,000`. Now, they call the `withdraw_token` function above and set `amount` to `u32::MAX-``100` (which is `41,294,967,195`). The arithmetic addition `amount + FEE` will wrap to `899`. That is certainly less than `100,000` so they’ll pass the check and the code will withdraw `amount` tokens from the vault, which is way more than the user initially deposited.

We can replace the `+` with `checked_add` to mitigate this issue:

```
let FEE: u32 = 1000; 

fn withdraw_token(program_id: &Pubkey, accounts: &[AccountInfo], amount: u32) -> ProgramResult {

    // ...
    // deserialize & validate user and vault accounts
    // ...
    
    if amount.checked_add(FEE).ok_or(ProgramError::InvalidArgument)? > vault.user_balance[user_id] {
        return Err(ProgramError::AttemptToWithdrawTooMuch);
    }
    
    // ...
    // Transfer `amount` many tokens from vault to user-controlled account ...
    // ...
    
    Ok(())
}
```

Now any arithmetic operation that would overflow will result in an error, and the transaction will be cancelled. Hence, this instruction is no longer exploitable.

Note that a similar problem can arise when using unchecked conversions between integer types. We’ve seen a few contracts use unchecked casts, e.g. via using `as u32` on a `u64` value. In cases like this, Rust will simply truncate the value to its last 32 bits, which can lead to unexpected behaviour.

Hence, avoid unchecked casts via `as <type>` and use checked conversions like `<type>::try_from(...)` instead.

### Arbitrary signed program invocation[¶](https://neodyme.io/en/blog/solana_common_pitfalls/#arbitrary-signed-program-invocation)

#### TL;DR[¶](https://neodyme.io/en/blog/solana_common_pitfalls/#tldr-3)

**Always** (!) verify the pubkey of any program you invoke via the `invoke_signed()` API.

#### Description[¶](https://neodyme.io/en/blog/solana_common_pitfalls/#description-3)

In many instructions, you will want to invoke foreign programs while signing with a program-owned account. A common use case for this is invoking the SPL program to transfer funds between token accounts. Solana design requires that any program you want to invoke has to be an instruction input and thus supplied by the user. Since a user is able to input an arbitrary program account, it is crucial to validate that you’re in fact dealing with the program you’re expecting.

#### Example[¶](https://neodyme.io/en/blog/solana_common_pitfalls/#example-3)

This instruction is supposed to withdraw `amount` tokens from the program-owned `vault` token account to a user-controlled account.

```
pub fn process_withdraw(program_id: &Pubkey, accounts: &[AccountInfo], amount: u64) -> ProgramResult {
        let account_info_iter = &mut accounts.iter();
        let vault = next_account_info(account_info_iter)?;
        let vault_authority = next_account_info(account_info_iter)?;
        let destination = next_account_info(account_info_iter)?;
        let token_program = next_account_info(account_info_iter)?;

        // ...
        // get signer seeds, validate account owners and signers, 
        // and verify that the user can withdraw the supplied amount
        // ...
    
        // invoke unverified token_program
        invoke_signed(
            &spl_token::instruction::transfer(
                &token_program.key,
                &vault.key,
                &destination.key,
                &vault_authority.key,
                &[&vault_authority.key],
                amount,
            )?,
            &[
                vault.clone(),
                destination.clone(),
                vault_owner_info.clone(),
                token_program.clone(),
            ],
            &[&seeds],
        )?;


        Ok(())
    }
```

In this example, an attacker can supply their own malicious fork of the SPL program as `token_program`. Their program would implement a `transfer` instruction that invokes the real SPL program but doesn’t actually transfer `amount` tokens to the destination account, but instead drains the entire vault into an attacker-controlled wallet.

To fix this, we simply need to check that the program we are invoking is, in fact, the one we want:

```
pub fn process_withdraw(program_id: &Pubkey, accounts: &[AccountInfo], amount: u64) -> ProgramResult {
        let account_info_iter = &mut accounts.iter();
        let vault = next_account_info(account_info_iter)?;
        let vault_authority = next_account_info(account_info_iter)?;
        let destination = next_account_info(account_info_iter)?;
        let token_program = next_account_info(account_info_iter)?;

        // ...
        // get signer seeds, validate account owners and signers, 
        // and verify that the user can withdraw the supplied amount
        // ...
    
        // verify that token_program is in fact the official spl token program
        if token_program.key != &spl_token::id() {
            return Err(ProgramError::InvalidTokenProgram);
        }    
    
        invoke_signed(
            &spl_token::instruction::transfer(
                &token_program.key,
                &vault.key,
                &destination.key,
                &vault_authority.key,
                &[&vault_authority.key],
                amount,
            )?,
            &[
                vault.clone(),
                destination.clone(),
                vault_owner_info.clone(),
                token_program.clone(),
            ],
            &[&seeds],
        )?;


        Ok(())
    }
```

Note that with spl-token v0.1.5, Solana has [introduced a hardcoded check](https://github.com/solana-labs/solana-program-library/pull/1714) to ensure SPL invocations can only use the real SPL program as `program_id`. However, this check **will not** mitigate this vulnerability if you’re invoking any program other than SPL or are using an outdated SPL version. If you’re unsure, inserting the above check is never wrong.

### Solana account confusions[¶](https://neodyme.io/en/blog/solana_common_pitfalls/#solana-account-confusions)

#### TL;DR[¶](https://neodyme.io/en/blog/solana_common_pitfalls/#tldr-4)

Always keep in mind that a user can supply arbitrary accounts as inputs. Even if an account is owned by the contract, you have to ensure that the account data has the type you expect it to have.

#### Description[¶](https://neodyme.io/en/blog/solana_common_pitfalls/#description-4)

Usually, your contract would implement multiple account types to store its state and data. Consequently, an owner check isn’t always sufficient to ensure you’re dealing with the account you’re expecting. You also have to verify that each account you are provided is, in fact, an account of the expected type.

Also, if you update your contract and change the data format of any of the account types you use, be sure to verify that the given account has the correct data format version (e.g., by introducing a new type for each changed account type).

#### Example[¶](https://neodyme.io/en/blog/solana_common_pitfalls/#example-4)

Consider this code defining and using two account types to store data:

```
// ------- Account Types -------- 
pub struct Config {
    pub admin: Pubkey,
    pub fee: u32,
    pub user_count: u32,
}

pub struct User {
    pub user_authority: Pubkey,
    pub balance: u64,
}

// ------- Helper functions --------
fn unpack_config(account: &AccountInfo) -> Result<Config, ProgramError> {
    let mut config: Config = deserialize(&mut account.data.borrow())?;

    return config;
}


// ------- Contract Instructions ---------
fn create_user(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let user = next_account_info(account_iter)?;    
   
    // ...
    // Initialize a User struct, set user_authority 
    // to user and set balance to 0
    // ...
    
    Ok(())
}

fn withdraw_tokens(program_id: &Pubkey, accounts: &[AccountInfo], amount: u64) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let vault = next_account_info(account_iter)?;
    let admin = next_account_info(account_iter)?;
    let config = unpack_config(next_account_info(account_iter)?)?;
    let vault_authority = next_account_info(account_iter)?;
    
    if config.owner != program_id {
        return Err(ProgramError::InvalidConfigAccount);
    }
    
    if config.admin != admin.pubkey() {
        return Err(ProgramError::InvalidAdminAccount);
    }
    
    // ...
    // Transfer funds from vault to admin using vault_authority
    // ...
    
    Ok(())
}
```

At first sight, the `withdraw_tokens` instruction seems sane. It validates that the `config` account is program-owned and then validates that the user-supplied `admin` account is the one in the `config` account. As we saw in the section on ownership checks, this means an attacker can’t just craft a malicious `config` account with an arbitrary `admin` field to bypass this check, since that fake account would not have the right owner. But there’s still a way to get around this.

An important thing to know is that Solana account data doesn’t know types. The account data is just an array of bytes and it’s up to each contract to deserialize those bytes into some custom account type.

Let’s have a closer look at our smart contract, specifically the `create_user` instruction. It allows a user to create a program-owned account of the `User` type and sets the `user_authority` field to a user-controlled value.

Now imagine what would happen if an attacker called `withdraw_tokens` but instead of providing the actual `Config` account as `config`, they supply the `User` account they just created. The program will call `unpack_config` on that `User` account to deserialize the data into a `Config` account. Keep in mind, the “data” is still just an array of bytes. The function `unpack_config` will simply take the first 32 bytes of account data and write them to the `admin` field of a `Config` struct, then it will take the next 4 bytes and write them to the `user_count` field of that same `Config` struct and, finally, it will take the last 4 bytes and write them to the `fee` field of the struct.

Hence this `User` account:

```
user_authority: 12345AAAAAAAAAAAAAAAAAAAAAAAAAAA;
balance: 0x1111111111111111
```

would become this `Config` account:

```
admin: 12345AAAAAAAAAAAAAAAAAAAAAAAAAAA
user_count: 0x11111111
fee: 0x11111111
```

In short: the `user_authority` becomes the `admin` field and the `balance` field gets split up into `user_count` and `fee`. This gives us a way to bypass the check in `withdraw_tokens`!

Suppose an attacker creates a `User` account (let’s call that account `user_x`) by calling `create_user`, where they set `user_authority` to a wallet they control (we’ll call it `wallet_x`). They can then invoke `withdraw_tokens` with `user_x` as the`config` account and `wallet_x` as `admin`. Since `user_x` has been created by the contract’s own `create_user` function, it’s a program owned account and will pass the owner check. And since the `config.admin` field in our fake `config` is `wallet_x`, the admin check will succeed as well.

The contract will hence happily transfer funds from the vault to `wallet_x`.

We can fix this issue by adding a type field to our structs:

```
// ------- Account Types -------- 
pub struct Config {
    pub TYPE: u8, // <-- should contain a unique identifier for this account type
    pub admin: Pubkey,
    pub fee: u32,
    pub user_count: u32,
}

pub struct User {
    pub TYPE: u8, // <-- should contain a unique identifier for this account type
    pub user_authority: Pubkey,
    pub balance: u64,
}
```

When we create a new account, we set the `TYPE` field to a value that is unique to accounts of that type. Our deserialization function will also have to validate the `TYPE` and error out if the account does not have the type we’re expecting.

```
// ------- Helper functions --------
fn unpack_config(account: &AccountInfo) -> Result<Config, ProgramError> {
    let mut config: Config = deserialize(&mut account.data.borrow())?;

    if config.TYPE != Types::ConfigType {
        return Err(ProgramError::InvalidAccountType); 
    }
    
    return config;
}
```

This effectively prevents confusion between accounts of different types.

A related pitfall is that if you update your contract and change the fields of any of the account types you are using, you must also ensure that there is no confusion between accounts that contain the old data format and accounts that contain the new data format. This can either be done using a separate `VERSION` field or by introducing a new type for each change (e.g., `<OldTypeName>v2`).

## Outro[¶](https://neodyme.io/en/blog/solana_common_pitfalls/#outro)

This concludes our list of the most common vulnerabilities in Solana programs. When we audit a contract, these are among the first things we check. We’ve seen all of these vulnerabilities numerous times, and they often led to exploits that could entirely drain the contract in question.

Of course, going through this list and checking for these bugs doesn’t constitute a full audit. We’ve merely listed the vulnerabilities that we encountered most often during our audits. There are many other classes of vulnerabilities that we have not listed here, many of which arise from more complex structures within a contract and hence cannot be identified via simple “checklist audits”.

In the coming weeks and months, we’ll be publishing write-ups for other interesting vulnerabilities. Watch this space!