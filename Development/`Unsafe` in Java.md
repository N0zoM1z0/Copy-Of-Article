# [Java中的魔法类-Unsafe](https://www.cnblogs.com/rickiyang/p/11334887.html)

Unsafe是位于sun.misc包下的一个类，主要提供一些用于执行低级别、不安全操作的方法，如直接访问系统内存资源、自主管理内存资源等，这些方法在提升Java运行效率、增强Java语言底层资源操作能力方面起到了很大的作用。

但是，这个类的作者不希望我们使用它，因为我们虽然我们获取到了对底层的控制权，但是也增大了风险，安全性正是Java相对于C++/C的优势。因为该类在`sun.misc`包下，默认是被**BootstrapClassLoader**加载的。如果我们在程序中去调用这个类的话，我们使用的类加载器肯定是 AppClassLoader,问题是在Unsafe中是这样写的：

```java
private static final Unsafe theUnsafe;

private Unsafe() {
}

@CallerSensitive
public static Unsafe getUnsafe() {
  Class var0 = Reflection.getCallerClass();
  if (!VM.isSystemDomainLoader(var0.getClassLoader())) {
    throw new SecurityException("Unsafe");
  } else {
    return theUnsafe;
  }
}
```

将构造函数私有，然后提供了一个静态方法去获取当前类实例。在`getUnsafe()`方法中首先判断当前类加载器是否为空，因为使用 BootstrapClassLoader 本身就是空，它是用c++实现的，这样就限制了我们在自己的代码中使用这个类。

但是同时作者也算是给我们提供了一个后门，因为Java有反射机制。调用的思路就是将`theUnsafe`对象设置为可见。

```java
Field theUnsafeField = Unsafe.class.getDeclaredField("theUnsafe");
theUnsafeField.setAccessible(true);
Unsafe unsafe = (Unsafe) theUnsafeField.get(null);
System.out.println(unsafe);
```

unsafe类功能介绍：

![img](https://img2018.cnblogs.com/blog/1607781/201908/1607781-20190811141555811-1035387188.png)

#### 内存操作

这部分主要包含堆外内存的分配、拷贝、释放、给定地址值操作等方法。

```java
//分配内存, 相当于C++的malloc函数
public native long allocateMemory(long bytes);
//扩充内存
public native long reallocateMemory(long address, long bytes);
//释放内存
public native void freeMemory(long address);
//在给定的内存块中设置值
public native void setMemory(Object o, long offset, long bytes, byte value);
//内存拷贝
public native void copyMemory(Object srcBase, long srcOffset, Object destBase, long destOffset, long bytes);
//获取给定地址值，忽略修饰限定符的访问限制。与此类似操作还有: getInt，getDouble，getLong，getChar等
public native Object getObject(Object o, long offset);
//为给定地址设置值，忽略修饰限定符的访问限制，与此类似操作还有: putInt,putDouble，putLong，putChar等
public native void putObject(Object o, long offset, Object x);
//获取给定地址的byte类型的值（当且仅当该内存地址为allocateMemory分配时，此方法结果为确定的）
public native byte getByte(long address);
//为给定地址设置byte类型的值（当且仅当该内存地址为allocateMemory分配时，此方法结果才是确定的）
public native void putByte(long address, byte x);
```

通常，我们在Java中创建的对象都处于堆内内存（heap）中，堆内内存是由JVM所管控的Java进程内存，并且它们遵循JVM的内存管理机制，JVM会采用垃圾回收机制统一管理堆内存。与之相对的是堆外内存，存在于JVM管控之外的内存区域，Java中对堆外内存的操作，依赖于Unsafe提供的操作堆外内存的native方法。

#### 使用堆外内存的原因

- 对垃圾回收停顿的改善。由于堆外内存是直接受操作系统管理而不是JVM，所以当我们使用堆外内存时，即可保持较小的堆内内存规模。从而在GC时减少回收停顿对于应用的影响。
- 提升程序I/O操作的性能。通常在I/O通信过程中，会存在堆内内存到堆外内存的数据拷贝操作，对于需要频繁进行内存间数据拷贝且生命周期较短的暂存数据，都建议存储到堆外内存。

#### 典型应用

DirectByteBuffer是Java用于实现堆外内存的一个重要类，通常用在通信过程中做缓冲池，如在Netty、MINA等NIO框架中应用广泛。DirectByteBuffer对于堆外内存的创建、使用、销毁等逻辑均由Unsafe提供的堆外内存API来实现。

下面的代码为DirectByteBuffer构造函数，创建DirectByteBuffer的时候，通过Unsafe.allocateMemory分配内存、Unsafe.setMemory进行内存初始化，而后构建Cleaner对象用于跟踪DirectByteBuffer对象的垃圾回收，以实现当DirectByteBuffer被垃圾回收时，分配的堆外内存一起被释放。

```java
DirectByteBuffer(int cap) {                   // package-private

  super(-1, 0, cap, cap);
  boolean pa = VM.isDirectMemoryPageAligned();
  int ps = Bits.pageSize();
  long size = Math.max(1L, (long)cap + (pa ? ps : 0));
  Bits.reserveMemory(size, cap);

  long base = 0;
  try {
    //分配内存，返回基地址
    base = unsafe.allocateMemory(size);
  } catch (OutOfMemoryError x) {
    Bits.unreserveMemory(size, cap);
    throw x;
  }
  //内存初始化
  unsafe.setMemory(base, size, (byte) 0);
  if (pa && (base % ps != 0)) {
    // Round up to page boundary
    address = base + ps - (base & (ps - 1));
  } else {
    address = base;
  }
  //跟踪directbytebuffer 对象的垃圾回收，实现堆外内存的释放
  cleaner = Cleaner.create(this, new Deallocator(base, size, cap));
  att = null;



}
```

上面最后一句代码通过`Cleaner.create()`来进行对象监控，释放堆外内存。这里是如何做到的呢？跟踪一下Cleaner类：

```java
public class Cleaner extends PhantomReference<Object> {
  
   public static Cleaner create(Object var0, Runnable var1) {
        return var1 == null ? null : add(new Cleaner(var0, var1));
    }
}
```

可以看到继承了`PhantomReference`，Java中的4大引用类型我们都知道。PhantomReference的作用于其他的Refenrence作用大有不同。像 SoftReference、WeakReference都是为了保证引用的类对象能在不用的时候及时的被回收，但是 PhantomReference 并不会决定对象的生命周期。如果一个对象仅持有虚引用，那么它就和没有任何引用一样，对象不可达时就会被垃圾回收器回收，但是任何时候都无法通过虚引用获得对象。虚引用主要用来跟踪对象被垃圾回收器回收的活动。

那他的作用到底是啥呢？准确来说 PhantomReference 给使用者提供了一种机制-来监控对象的垃圾回收的活动。

可能这样说不是太明白，我来举个例子：

```java
package com.rickiyang.learn.javaagent;

import java.lang.ref.PhantomReference;
import java.lang.ref.Reference;
import java.lang.ref.ReferenceQueue;
import java.lang.reflect.Field;


/**
 * @author rickiyang
 * @date 2019-08-08
 * @Desc
 */
public class TestPhantomReference {
  public static boolean isRun = true;

  public static void main(String[] args) throws Exception {
    String str = new String("123");
    System.out.println(str.getClass() + "@" + str.hashCode());
    final ReferenceQueue<String> referenceQueue = new ReferenceQueue<>();
    new Thread(() -> {
      while (isRun) {
        Object obj = referenceQueue.poll();
        if (obj != null) {
          try {
            Field rereferent = Reference.class.getDeclaredField("referent");
            rereferent.setAccessible(true);
            Object result = rereferent.get(obj);
            System.out.println("gc will collect："
                               + result.getClass() + "@"
                               + result.hashCode() + "\t"
                               + result);
          } catch (Exception e) {
            e.printStackTrace();
          }
        }
      }
    }).start();
    PhantomReference<String> weakRef = new PhantomReference<>(str, referenceQueue);
    str = null;
    Thread.currentThread().sleep(2000);
    System.gc();
    Thread.currentThread().sleep(2000);
    isRun = false;
  }
}
```

上面这段代码的含义是new PhantomReference()，因为PhantomReference必须的维护一个ReferenceQueue用来保存当前被虚引用的对象。上例中手动去调用`referenceQueue.poll()`方法，这里你需要注意的是并不是我们主动去释放queue中的对象，你跟踪进去 poll() 方法可以看到有一个全局锁对象，只有当当前对象失去了引用之后才会释放锁，poll()方法才能执行。在执行poll()方法释放对象的时候我们可以针对这个对象做一些监控。这就是 PhantomReference 的意义所在。

说回到 Cleaner， 通过看源码，`create()`方法调用了`add()`方法，在Cleaner类里面维护了一个双向链表，将每一个add进来的Cleaner对象都添加到这个链表中维护。那么在Cleaner 链表中的对象实在何时被释放掉呢？

注意到 Cleaner中有一个clean()方法：

```java
public void clean() {
  if (remove(this)) {
    try {
      this.thunk.run();
    } catch (final Throwable var2) {
      AccessController.doPrivileged(new PrivilegedAction<Void>() {
        public Void run() {
          if (System.err != null) {
            (new Error("Cleaner terminated abnormally", var2)).printStackTrace();
          }

          System.exit(1);
          return null;
        }
      });
    }

  }
}
```

remove()方法是将该对象从内部维护的双向链表中清除。下面紧跟着是`thunk.run()` ，thunk = 我们通过`create()`方法传进来的参数，在``DirectByteBuffer中`那就是：`Cleaner.create(this, new Deallocator(base, size, cap))`,Deallocator类也是一个线程：

```java
private static class Deallocator
        implements Runnable
    {

        private static Unsafe unsafe = Unsafe.getUnsafe();

       //省略无关 代码
        public void run() {
            if (address == 0) {
                // Paranoia
                return;
            }
            unsafe.freeMemory(address);
            address = 0;
            Bits.unreserveMemory(size, capacity);
        }

    }
```

看到在run方法中调用了`freeMemory()`去释放掉对象。

在 `Reference`类中调用了该方法，Reference 类中的静态代码块 有个一内部类：`ReferenceHandler`,它继承了 Thread，在run方法中调用了 `tryHandlePending()`，并且被设置为守护线程，意味着会循环不断的处理pending链表中的对象引用。

这里要注意的点是：

**Cleaner本身不带有清理逻辑，所有的逻辑都封装在thunk中，因此thunk是怎么实现的才是最关键的。**

```java
static {
  ThreadGroup tg = Thread.currentThread().getThreadGroup();
  for (ThreadGroup tgn = tg;
       tgn != null;
       tg = tgn, tgn = tg.getParent());
  Thread handler = new ReferenceHandler(tg, "Reference Handler");
  /* If there were a special system-only priority greater than
         * MAX_PRIORITY, it would be used here
         */
  handler.setPriority(Thread.MAX_PRIORITY);
  handler.setDaemon(true);
  handler.start();

  // provide access in SharedSecrets
  SharedSecrets.setJavaLangRefAccess(new JavaLangRefAccess() {
    @Override
    public boolean tryHandlePendingReference() {
      return tryHandlePending(false);
    }
  });
}


static boolean tryHandlePending(boolean waitForNotify) {
  Reference<Object> r;
  Cleaner c;
  try {
    synchronized (lock) {
      if (pending != null) {
        r = pending;
        //如果当前Reference对象是Cleaner类型的就进行特殊处理
        c = r instanceof Cleaner ? (Cleaner) r : null;
        // unlink 'r' from 'pending' chain
        pending = r.discovered;
        r.discovered = null;
      } else {
        // The waiting on the lock may cause an OutOfMemoryError
        // because it may try to allocate exception objects.
        if (waitForNotify) {
          lock.wait();
        }
        // retry if waited
        return waitForNotify;
      }
    }
  } catch (OutOfMemoryError x) {
    Thread.yield();
    // retry
    return true;
  } catch (InterruptedException x) {
    // retry
    return true;
  }

  // clean 不为空的时候，走清理的逻辑
  if (c != null) {
    c.clean();
    return true;
  }

  ReferenceQueue<? super Object> q = r.queue;
  if (q != ReferenceQueue.NULL) q.enqueue(r);
  return true;
}
```

`tryHandlePending`这段代码的意思是：

如果一个对象经过JVM检测他已经没有强引用了，但是还有 弱引用 或者 软引用 或者 虚引用的情况下，那么就会把此对象放到一个名为pending的链表里，这个链表是通过Reference.discovered域连接在一起的。

`ReferenceHandler`这个线程会一直从链表中取出被pending的对象，它可能是WeakReference，也可能是SoftReference，当然也可能是PhantomReference和Cleaner。如果是Cleaner，那就直接调用Cleaner的clean方法，然后就结束了。其他的情况下，要交给这个对象所关联的queue，以便于后续的处理。

关于堆外内存分配和回收的代码我们就先分析到这里。需要注意的是对外内存回收的时机也是不确定的，所以不要持续分配一些大对象到堆外，如果没有被回收掉，这是一件很可怕的事情。毕竟它无法被JVM检测到。

#### 内存屏障

硬件层的内存屏障分为两种：`Load Barrier` 和 `Store Barrier`即读屏障和写屏障。内存屏障有两个作用：阻止屏障两侧的指令重排序；强制把写缓冲区/高速缓存中的脏数据等写回主内存，让缓存中相应的数据失效。在Unsafe中提供了三个方法来操作内存屏障：

```java
//读屏障，禁止load操作重排序。屏障前的load操作不能被重排序到屏障后，屏障后的load操作不能被重排序到屏障前
public native void loadFence();
//写屏障，禁止store操作重排序。屏障前的store操作不能被重排序到屏障后，屏障后的store操作不能被重排序到屏障前
public native void storeFence();
//全能屏障，禁止load、store操作重排序
public native void fullFence();
```

先简单了解两个指令：

- Store：将处理器缓存的数据刷新到内存中。
- Load：将内存存储的数据拷贝到处理器的缓存中。

JVM平台提供了一下几种内存屏障：

| 屏障类型            | 指令示例                 | 说明                                                         |
| :------------------ | :----------------------- | :----------------------------------------------------------- |
| LoadLoad Barriers   | Load1;LoadLoad;Load2     | 该屏障确保Load1数据的装载先于Load2及其后所有装载指令的的操作 |
| StoreStore Barriers | Store1;StoreStore;Store2 | 该屏障确保Store1立刻刷新数据到内存(使其对其他处理器可见)该操作先于Store2及其后所有存储指令的操作 |
| LoadStore Barriers  | Load1;LoadStore;Store2   | 确保Load1的数据装载先于Store2及其后所有的存储指令刷新数据到内存的操作 |
| StoreLoad Barriers  | Store1;StoreLoad;Load2   | 该屏障确保Store1立刻刷新数据到内存的操作先于Load2及其后所有装载装载指令的操作。它会使该屏障之前的所有内存访问指令(存储指令和访问指令)完成之后,才执行该屏障之后的内存访问指令 |

StoreLoad Barriers同时具备其他三个屏障的效果，因此也称之为`全能屏障`（mfence），是目前大多数处理器所支持的；但是相对其他屏障，该屏障的开销相对昂贵。

**loadFence**

实现了LoadLoad Barriers，该操作禁止了指令的重排序。

**storeFence**

实现了 StoreStore Barriers，确保屏障前的写操作能够立刻刷入到主内存，并且确保屏障前的写操作一定先于屏障后的写操作。即保证了内存可见性和禁止指令重排序。

**fullFence**

实现了 StoreLoad Barriers，强制所有在mfence指令之前的store/load指令，都在该mfence指令执行之前被执行；所有在mfence指令之后的store/load指令，都在该mfence指令执行之后被执行。

在 JDK 中调用了 内存屏障这几个方法的实现类有 `StampedLock`。关于`StampedLock`的实现我们后面会专门抽出一篇去讲解。它并没有去实现AQS队列。而是采用了 其他方式实现。

#### 系统相关

这部分包含两个获取系统相关信息的方法。

```java
//返回系统指针的大小。返回值为4（32位系统）或 8（64位系统）。
public native int addressSize();  
//内存页的大小，此值为2的幂次方。
public native int pageSize();
```

在 `java.nio`下的Bits类中调用了`pagesize()方法计算系统中页大小：`

```java
private static int pageSize = -1;

static int pageSize() {
    if (pageSize == -1)
        pageSize = unsafe().pageSize();
    return pageSize;
}
```

#### 线程调度

线程调度中提供的方法包括：线程的挂起，恢复 和 对象锁机制等，其中获取对象的监视器锁方法已经被标记为弃用。

```java
// 终止挂起的线程，恢复正常.java.util.concurrent包中挂起操作都是在LockSupport类实现的，其底层正是使用这两个方法
public native void unpark(Object thread);
// 线程调用该方法，线程将一直阻塞直到超时，或者是中断条件出现。
public native void park(boolean isAbsolute, long time);
//获得对象锁（可重入锁）
@Deprecated
public native void monitorEnter(Object o);
//释放对象锁
@Deprecated
public native void monitorExit(Object o);
//尝试获取对象锁
@Deprecated
public native boolean tryMonitorEnter(Object o);
```

将一个线程进行挂起是通过 park 方法实现的，调用`park()`后，线程将一直 **阻塞** 直到 **超时** 或者 **中断** 等条件出现。`unpark`可以释放一个被挂起的线程，使其恢复正常。整个并发框架中对线程的挂起操作被封装在`LockSupport`类中，LockSupport 类中有各种版本 pack 方法，但最终都调用了`Unsafe.park()`方法。 我们来看一个例子：

```java
package leetcode;

import sun.misc.Unsafe;

import java.lang.reflect.Field;
import java.util.concurrent.TimeUnit;

/**
 * @author: rickiyang
 * @date: 2019/8/10
 * @description:
 */
public class TestUsafe {

    private static Thread mainThread;


    public Unsafe getUnsafe() throws Exception {
        Field theUnsafeField = Unsafe.class.getDeclaredField("theUnsafe");
        theUnsafeField.setAccessible(true);
        return (Unsafe) theUnsafeField.get(null);
    }

    public void testPark() throws Exception {
        Unsafe unsafe = getUnsafe();
        mainThread = Thread.currentThread();

        System.out.println(String.format("park %s", mainThread.getName()));
        unsafe.park(false, TimeUnit.SECONDS.toNanos(3));

        new Thread(() -> {
            System.out.println(String.format("%s unpark %s", Thread.currentThread().getName(),
                                             mainThread.getName()));
            unsafe.unpark(mainThread);
        }).start();
        System.out.println("main thread is done");

    }

    public static void main(String[] args) throws Exception {
        TestUsafe testUsafe = new TestUsafe();
        testUsafe.testPark();
    }

}
```

运行上面的例子，那你会发现在第29行 `park`方法设置了超时时间为3秒后，会阻塞当前主线程，直到超时时间到达，下面的代码才会继续执行。

#### 对象操作

Unsafe类中提供了多个方法来进行 对象实例化 和 获取对象的偏移地址 的操作：

```java
// 传入一个Class对象并创建该实例对象，但不会调用构造方法
public native Object allocateInstance(Class<?> cls) throws InstantiationException;

// 获取字段f在实例对象中的偏移量
public native long objectFieldOffset(Field f);

// 返回值就是f.getDeclaringClass()
public native Object staticFieldBase(Field f);
// 静态属性的偏移量，用于在对应的Class对象中读写静态属性
public native long staticFieldOffset(Field f);

// 获得给定对象偏移量上的int值，所谓的偏移量可以简单理解为指针指向该变量；的内存地址，
// 通过偏移量便可得到该对象的变量，进行各种操作
public native int getInt(Object o, long offset);
// 设置给定对象上偏移量的int值
public native void putInt(Object o, long offset, int x);

// 获得给定对象偏移量上的引用类型的值
public native Object getObject(Object o, long offset);
// 设置给定对象偏移量上的引用类型的值
public native void putObject(Object o, long offset, Object x););

// 设置给定对象的int值，使用volatile语义，即设置后立马更新到内存对其他线程可见
public native void putIntVolatile(Object o, long offset, int x);
// 获得给定对象的指定偏移量offset的int值，使用volatile语义，总能获取到最新的int值。
public native int getIntVolatile(Object o, long offset);

// 与putIntVolatile一样，但要求被操作字段必须有volatile修饰
public native void putOrderedInt(Object o, long offset, int x);
```

`allocateInstance`方法在这几个场景下很有用：跳过对象的实例化阶段（通过构造函数）、忽略构造函数的安全检查（反射newInstance()时）、你需要某类的实例但该类没有public的构造函数。

举个例子：

```java
public class User {

    private String name;
    private int age;
    private static String address = "beijing";

    public User(){
        name = "xiaoming";
    }

    public String getname(){
        return name;
    }
}

	/**
     * 实例化对象
     * @throws Exception
     */
public void newInstance() throws Exception{
    TestUsafe testUsafe = new TestUsafe();
    Unsafe unsafe = testUsafe.getUnsafe();
    User user = new User();
    System.out.println(user.getname());

    User user1 = User.class.newInstance();
    System.out.println(user1.getname());

    User o = (User)unsafe.allocateInstance(User.class);
    System.out.println(o.getname());
}
```

打印的结果可以看到最后输出的是null，说明构造函数未被加载。可以进一步实验，将User类中的构造函数设置为 private，你会发现在前面两种实例化方式检查期就报错。但是第三种是可以用的。这是因为`allocateInstance`只是给对象分配了内存，它并不会初始化对象中的属性。

下面是对象操作的使用示例：

```java
public void testObject() throws Exception{
    TestUsafe testUsafe = new TestUsafe();
    Unsafe unsafe = testUsafe.getUnsafe();

    //通过allocateInstance创建对象,为其分配内存地址，不会加载构造函数
    User user = (User) unsafe.allocateInstance(User.class);
    System.out.println(user);

    // Class && Field
    Class<? extends User> userClass = user.getClass();
    Field name = userClass.getDeclaredField("name");
    Field age = userClass.getDeclaredField("age");
    Field location = userClass.getDeclaredField("address");

    // 获取实例域name和age在对象内存中的偏移量并设置值
    System.out.println(unsafe.objectFieldOffset(name));
    unsafe.putObject(user, unsafe.objectFieldOffset(name), "xiaoming");
    System.out.println(unsafe.objectFieldOffset(age));
    unsafe.putInt(user, unsafe.objectFieldOffset(age), 18);
    System.out.println(user);

    // 获取定义location字段的类
    Object staticFieldBase = unsafe.staticFieldBase(location);
    System.out.println(staticFieldBase);

    // 获取static变量address的偏移量
    long staticFieldOffset = unsafe.staticFieldOffset(location);
    // 获取static变量address的值
    System.out.println(unsafe.getObject(staticFieldBase, staticFieldOffset));
    // 设置static变量address的值
    unsafe.putObject(staticFieldBase, staticFieldOffset, "tianjin");
    System.out.println(user + " " + user.getAddress());
}
```

**对象实例布局与内存大小**

一个Java对象占用多大的内存空间呢？这个问题很值得读者朋友去查一下。 因为这个输出本篇的重点所以简单说一下。一个 Java 对象在内存中由对象头、示例数据和对齐填充构成。对象头存储了对象运行时的基本数据，如 hashCode、锁状态、GC 分代年龄、类型指针等等。实例数据是对象中的非静态字段值，可能是一个原始类型的值，也可能是一个指向其他对象的指针。对齐填充就是 padding，保证对象都采用 8 字节对齐。除此以外，在 64 位虚拟机中还可能会开启指针压缩，将 8 字节的指针压缩为 4 字节，这里就不再过多介绍了。

也就是说一个 Java 对象在内存中，首先是对象头，然后是各个类中字段的排列，这之间可能会有 padding 填充。这样我们大概就能理解字段偏移量的含义了，它实际就是每个字段在内存中所处的位置。

```java
public class User {

    private String name;
    private int age;
}

TestUsafe testUsafe = new TestUsafe();
Unsafe unsafe = testUsafe.getUnsafe();

for (Field field : User.class.getDeclaredFields()) {
    System.out.println(field.getName() + "-" + field.getType() + ": " + unsafe.objectFieldOffset(field));
}

结果：
name-class java.lang.String: 16
age-int: 12
```

从上面的运行结果中可以：
age：偏移值为12，即前面 12 个字节的对象头；

name：name从16字节开始，因为int 类型的age占了4个字节。

继续算下去整个对象占用的空间，对象头12，age 4，name 是指针类型，开启指针压缩占用4个字节，那么User对象整个占用20字节，因为上面说的padding填充，必须8字节对齐，那么实际上会补上4个字节的填充，即一共占用了24个字节。

按照这种计算方式，我们可以字节写一个计算size的工具类：

```java
public static long sizeOf(Object o) throws Exception{
    TestUsafe testUsafe = new TestUsafe();
    Unsafe unsafe = testUsafe.getUnsafe();
    HashSet<Field> fields = new HashSet<Field>();
    Class c = o.getClass();
    while (c != Object.class) {
        for (Field f : c.getDeclaredFields()) {
            if ((f.getModifiers() & Modifier.STATIC) == 0) {
                fields.add(f);
            }
        }
        //如果有继承父类的话，父类中的属性也是要计算的
        c = c.getSuperclass();
    }
    //计算每个字段的偏移量，因为第一个字段的偏移量即在对象头的基础上偏移的
    //所以只需要比较当前偏移量最大的字段即表示这是该对象最后一个字段的位置
    long maxSize = 0;
    for (Field f : fields) {
        long offset = unsafe.objectFieldOffset(f);
        if (offset > maxSize) {
            maxSize = offset;
        }
    }
    //上面计算的是对象最后一个字段的偏移量起始位置，java中对象最大长度是8个字节(long)
    //这里的计算方式是 将 当前偏移量 / 8 + 8字节 的padding
    return ((maxSize/8) + 1) * 8;
}
```

上面的工具类计算的结果也是24。

#### class相关操作

```java
//静态属性的偏移量，用于在对应的Class对象中读写静态属性
public native long staticFieldOffset(Field f);
//获取一个静态字段的对象指针
public native Object staticFieldBase(Field f);
//判断是否需要初始化一个类，通常在获取一个类的静态属性的时候（因为一个类如果没初始化，它的静态属性也不会初始化）使用。 当且仅当ensureClassInitialized方法不生效时返回false
public native boolean shouldBeInitialized(Class<?> c);
//确保类被初始化
public native void ensureClassInitialized(Class<?> c);
//定义一个类，可用于动态创建类，此方法会跳过JVM的所有安全检查，默认情况下，ClassLoader（类加载器）和ProtectionDomain（保护域）实例来源于调用者
public native Class<?> defineClass(String name, byte[] b, int off, int len,
                                   ClassLoader loader,
                                   ProtectionDomain protectionDomain);
//定义一个匿名类，可用于动态创建类
public native Class<?> defineAnonymousClass(Class<?> hostClass, byte[] data, Object[] cpPatches);
```

#### 数组 操作

数组操作主要有两个方法：

```java
//返回数组中第一个元素的偏移地址
public native int arrayBaseOffset(Class<?> arrayClass);
//返回数组中一个元素占用的大小
public native int arrayIndexScale(Class<?> arrayClass);
```

#### CAS操作

相信所有的开发者对这个词都不陌生，在AQS类中使用了无锁的方式来进行并发控制，主要就是CAS的功劳。

CAS的全称是Compare And Swap 即比较交换，其算法核心思想如下

> 执行函数：CAS(V,E,N)

包含3个参数

1. V表示要更新的变量
2. E表示预期值
3. N表示新值

如果V值等于E值，则将V的值设为N。若V值和E值不同，则说明已经有其他线程做了更新，则当前线程什么都不做。通俗的理解就是CAS操作需要我们提供一个期望值，当期望值与当前线程的变量值相同时，说明没有别的线程修改该值，当前线程可以进行修改，也就是执行CAS操作，但如果期望值与当前线程不符，则说明该值已被其他线程修改，此时不执行更新操作，但可以选择重新读取该变量再尝试再次修改该变量，也可以放弃操作。

Unsafe类中提供了三个方法来进行CAS操作：

```java
public final native boolean compareAndSwapObject(Object o, long offset,  Object expected, Object update);

public final native boolean compareAndSwapInt(Object o, long offset, int expected,int update);
  
public final native boolean compareAndSwapLong(Object o, long offset, long expected, long update);
```

另外，在 JDK1.8中新增了几个 CAS 的方法，他们的实现是基于上面三个方法做的一层封装：

```java
 //1.8新增，给定对象o，根据获取内存偏移量指向的字段，将其增加delta，
 //这是一个CAS操作过程，直到设置成功方能退出循环，返回旧值
 public final int getAndAddInt(Object o, long offset, int delta) {
     int v;
     do {
         //获取内存中最新值
         v = getIntVolatile(o, offset);
       //通过CAS操作
     } while (!compareAndSwapInt(o, offset, v, v + delta));
     return v;
 }

//1.8新增，方法作用同上，只不过这里操作的long类型数据
 public final long getAndAddLong(Object o, long offset, long delta) {
     long v;
     do {
         v = getLongVolatile(o, offset);
     } while (!compareAndSwapLong(o, offset, v, v + delta));
     return v;
 }

 //1.8新增，给定对象o，根据获取内存偏移量对于字段，将其 设置为新值newValue，
 //这是一个CAS操作过程，直到设置成功方能退出循环，返回旧值
 public final int getAndSetInt(Object o, long offset, int newValue) {
     int v;
     do {
         v = getIntVolatile(o, offset);
     } while (!compareAndSwapInt(o, offset, v, newValue));
     return v;
 }

// 1.8新增，同上，操作的是long类型
 public final long getAndSetLong(Object o, long offset, long newValue) {
     long v;
     do {
         v = getLongVolatile(o, offset);
     } while (!compareAndSwapLong(o, offset, v, newValue));
     return v;
 }

 //1.8新增，同上，操作的是引用类型数据
 public final Object getAndSetObject(Object o, long offset, Object newValue) {
     Object v;
     do {
         v = getObjectVolatile(o, offset);
     } while (!compareAndSwapObject(o, offset, v, newValue));
     return v;
 }
```

CAS在java.util.concurrent.atomic相关类、Java AQS、CurrentHashMap等实现上有非常广泛的应用。