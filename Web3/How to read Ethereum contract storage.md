Everybody is talking that data in contracts are public, but not everybody knows how to read it.

All contracts deployed to ethereum VM has dedicated storage where stores state. Here is an example how to read this storage with the *web3.js* library using *eth.getStorageAt()* method.

Contract example which we examine:

![img](https://miro.medium.com/v2/resize:fit:723/1*abjfd6Mq39EZGEhB9OhLzA.png)

This contract is deployed in **ropsten test net**: at *0xf1f5896ace3a78c347eb7eab503450bc93bd0c3b*

All parameters in the storage are indexed from the beginning. One index takes 256 bytes ant it fits 64 symbols. In this example, we have 10 parameters and we can iterate them:

```
let contractAddress = '0xf1f5896ace3a78c347eb7eab503450bc93bd0c3b'
for (index = 0; index < 10; index++){
 console.log(`[${index}]` + 
   web3.eth.getStorageAt(contractAddress, index))
}result:
[0] 0x000000000000000000000000000000000000000000000000000000000000000f
[1] 0x00000000000000000000000059b92d9a0000000000000000000000000000429f
[2] 0x0000000000000000000000000000000074657374310000000000000000000000
[3] 0x7465737431323336000000000000000000000000000000000000000000000000
[4] 0x6c65747320737472696e6720736f6d657468696e67000000000000000000002a
[5] 0x0000000000000000000000000000000000000000000000000000000000000000
[6] 0x0000000000000000000000000000000000000000000000000000000000000000
[7] 0x0000000000000000000000000000000000000000000000000000000000000002
[8] 0x0000000000000000000000000000000000000000000000000000000000000002
[9] 0x0000000000000000000000000000000000000000000000000000000000000000
```

Let`s have a deeper look into each parameter

## Index 0 — storeduint1

```
let contractAddress = '0xf1f5896ace3a78c347eb7eab503450bc93bd0c3b'
let index = 0console.log(web3.eth.getStorageAt(contractAddress, index))
console.log('DEC:' + web3.toDecimal(web3.eth.getStorageAt(contractAddress, index)))result:
0x000000000000000000000000000000000000000000000000000000000000000f
DEC:15
```

## constuint

Constants are not stored in a storage. Available only in code.

## Index 1 — investmentsLimit, investmentsDeadlineTimeStamp

```
let index = 1
console.log(web3.eth.getStorageAt(contractAddress, index))result:
 0x00000000000000000000000059b92d9a0000000000000000000000000000429f
DEC:  1505308058   and  17055
```

In index 1 is merged 2 properties to optimize storage usage.

## index 2 — string1

```
index = 2
console.log(web3.eth.getStorageAt(contractAddress, index))
console.log('ASCII: ' +
 web3.toAscii(web3.eth.getStorageAt(contractAddress, index)))result: 
0x0000000000000000000000000000000074657374310000000000000000000000
ASCII: test1
```

## index 3 — string2

```
index = 3
console.log(web3.eth.getStorageAt(contractAddress, index))
console.log('ASCII: ' +
 web3.toAscii(web3.eth.getStorageAt(contractAddress, index)))result:
0x7465737431323336000000000000000000000000000000000000000000000000
ASCII: test1236
```

## index 4— string3

```
index = 4
console.log(web3.eth.getStorageAt(contractAddress, index))
console.log('ASCII: ' +
 web3.toAscii(web3.eth.getStorageAt(contractAddress, index)))result:
0x6c65747320737472696e6720736f6d657468696e67000000000000000000002a
ASCII: lets string something         * (42)
```

End symbol *2a (dec 42)* is length of the stored string. (more details http://solidity.readthedocs.io/en/latest/miscellaneous.html#layout-of-state-variables-in-storage)

## index 5 — uints1

```
index = 5
console.log(web3.eth.getStorageAt(contractAddress, index))result:
0x0000000000000000000000000000000000000000000000000000000000000000PROBLEM!!!!
```

Mappings have a different indexation and should be read in other way. To read mapping value you should know the **key** value. Otherwise, read mapping value is impossible.

```
index = '0000000000000000000000000000000000000000000000000000000000000005'
key =  '00000000000000000000000xbccc714d56bc0da0fd33d96d2a87b680dd6d0df6'let newKey =  web3.sha3(key + index, {"encoding":"hex"})console.log(web3.eth.getStorageAt(contractAddress, newKey))
console.log('DEC: ' + web3.toDecimal(web3.eth.getStorageAt(contractAddress, newKey)))result:
0x0000000000000000000000000000000000000000000000000000000000000058
DEC: 88
```

## index6 — structs1

```
index = "0000000000000000000000000000000000000000000000000000000000000006"
key =  "00000000000000000000000xbccc714d56bc0da0fd33d96d2a87b680dd6d0df6"let newKey =  web3.sha3(key + index, {"encoding":"hex"})
console.log(web3.eth.getStorageAt(contractAddress, newKey))
console.log('ASCII: ' +
 web3.toAscii(web3.eth.getStorageAt(contractAddress, newKey)))result:
0x6465766963654272616e64000000000000000000000000000000000000000016
ASCII: deviceBrand
```

To read second struct value you need to increase *newKey* value by 1

```
function increaseHexByOne(hex) {
 let x = new BigNumber(hex)
 let sum = x.add(1)
 let result = '0x' + sum.toString(16)
 return result
}index = "0000000000000000000000000000000000000000000000000000000000000006"
key =  "00000000000000000000000xbccc714d56bc0da0fd33d96d2a87b680dd6d0df6"let newKey =  increaseHexByOne(
  web3.sha3(key + index, {"encoding":"hex"}))console.log(web3.eth.getStorageAt(contractAddress,newKey))
console.log('ASCII: ' +
 web3.toAscii(web3.eth.getStorageAt(contractAddress, newKey)))result:
0x6465766963655965617200000000000000000000000000000000000000000014
ASCII: deviceYear
```

If you want third struct value increase *newKey* once more.

## index 7— uintarray

```
index = "7"
console.log(web3.eth.getStorageAt(contractAddress, index))result:
  0x0000000000000000000000000000000000000000000000000000000000000002
```

This array has 2 items

```
index = "0000000000000000000000000000000000000000000000000000000000000007"
let newKey = web3.sha3(index, {"encoding":"hex"})console.log(web3.eth.getStorageAt(contractAddress, newKey))
console.log('DEC: ' +
  web3.toDecimal(web3.eth.getStorageAt(contractAddress, newKey)))result:
0x0000000000000000000000000000000000000000000000000000000000001f40
DEC: 8000
newKey = increaseHexByOne(web3.sha3(index, {"encoding":"hex"}))console.log(web3.eth.getStorageAt(contractAddress, newKey))
console.log('DEC: ' +
  web3.toDecimal(web3.eth.getStorageAt(contractAddress, newKey)))result:
0x0000000000000000000000000000000000000000000000000000000000002328
DEC: 9000
```

## index 8— deviceDataArray

```
index = "0000000000000000000000000000000000000000000000000000000000000008"let newKey = web3.sha3(index, {"encoding":"hex"})console.log(web3.eth.getStorageAt(contractAddress, newKey))
console.log('ASCII: ' +
 web3.toAscii(web3.eth.getStorageAt(contractAddress, newKey)))result:
0x6465766963654272616e64000000000000000000000000000000000000000016
ASCII: deviceBrand
index = "0000000000000000000000000000000000000000000000000000000000000008"let newKey = increaseHexByOne(web3.sha3(index, {"encoding":"hex"}))console.log(web3.eth.getStorageAt(contractAddress, newKey))
console.log('ASCII: ' +
web3.toAscii(web3.eth.getStorageAt(contractAddress, newKey)))result:
0x6465766963655965617200000000000000000000000000000000000000000014
ASCII: deviceYear
```

Increase by 2 result:

0x776561724c6576656c0000000000000000000000000000000000000000000012

ASCII: wearLevel

Increase by 3 you enter to second item into array result:

0x6465766963654272616e64320000000000000000000000000000000000000018

ASCII: deviceBrand2

Sources:
https://github.com/ethereum/solidity/issues/1550
https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_getstorageat
https://ethereum.stackexchange.com/questions/13910/how-to-read-a-private-variable-from-a-contract
https://github.com/ethereum/web3.js/issues/445