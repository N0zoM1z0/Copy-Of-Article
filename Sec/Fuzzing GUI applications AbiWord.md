Usually there is no problem if you want to fuzz a headless application. A headless application can be run just in a terminal, and doesn’t have any GUI. You can pick up your favorite fuzzer, and feed fuzzed data to the application. Normally, a headless application just processes data, and then quits or crashes right away. But it may be different if you are trying to fuzz an application with GUI. Let’s try to fuzz an open source text editor AbiWord.

There may be a couple of problems with fuzzing a GUI application. A GUI application may continue working after you feed an invalid data to it. Usually it’s a normal behavior for a GUI application. For example, you can try to open an invalid document in AbiWord. Then, it just lets you know that it could not open the document, and continues working (the AbiWord main window is still there). That’s an expected and correct behavior.

But while fuzzing we want to feed an application lots of invalid data. If we have to close the application manually each time when it opens an invalid document, it’s probably not what we want.

Another problem is that a lot of new windows are going to pop up while fuzzing. If you have a dedicated machine for fuzzing, then it should not be a problem. But if you use the same computer for fuzzing and other business, then lots of opening windows will definitely annoy you.

Some applications have a batch mode. Basically, it may be possible to use this application as a command line tool. For example, AbiWord supports converting a document to another format:

```
$ abiword --help
Usage:
  abiword [OPTION...] [FILE...] - commandline options

Help Options:
  -h, --help Show help options
  --help-all Show all help options
  --help-gtk Show GTK+ Options

Application Options:
  -g, --geometry=GEOMETRY Set initial frame geometry
  -t, --to=FORMAT Target format of the file 
                              (abw, zabw, rtf, txt, utf8, html, ...), 
                              depends on available filter plugins
```

You can ask it to convert a fuzzed document to another format. It’s going to parse the document to be able to convert it, but it’s not going to render it. That’s may be fine, but this approach doesn’t allow you to cover code which is responsible for rendering, so that you may miss some bugs. That’s not good.

There are a couple of solutions for the problems above.

# Use a virtual display

First, let’s get rid of annoying windows. There is an Xvfb command on *nix which creates a virtual display. It’s available on Ubuntu for sure. Here is an example how you can create a virtual display “:1”

```
Xvfb :1 -screen 0 1024x768x16
```

Then you can make your application use this display. Some applications may have a command line option which specifies a display to use. Or, you can try to put “:1” to DISPLAY variable.

To make sure that your application is actually using a virtual display, and rendering its stuff there, you can take a screenshot with commands like the following:

```
import -display :1 -window root image.png
display image.png
```

The first command takes a screenshot, and saves the result to ‘image.png’ file. The second command just displays ‘image.png’.

# Use timeout command

Now we are not going to see annoying windows created by our application while fuzzing. But it’s still going to wait for us to close it. Probably, the simplest solution is to kill the application by timeout. It can be easily done with a ‘timeout’ command on *nix. Here is an example of script for fuzzing AbiWord with zzuf fuzzer which uses ‘timeout’ command to kill AbiWord by timeout:

```
#!/bin/bash

seed=${1}
while [${seed} != 10000000]; do
    echo "seed: ${seed}"
    ${ZZUF_HOME}/bin/zzuf -c -s${seed} -r0.001:0.003 < test.doc > corrupted.doc
    ASAN_OPTIONS="detect_leaks=0" timeout 2s ${ABIWORD} \
        --display=:1 corrupted.doc > log 2>&1
    if grep AddressSanitizer log > /dev/null 2>&1 ; then
        # ASan found something

        echo "Game over"
        break
    fi
    seed=`expr ${seed} + 1`
done
```

Let me briefly describe what’s happening here:

1. The script starts a while loop where it increments a seed for zzuf fuzzer. It prints the seed for each iteration, so that all failures can be then easily reproduced (just run zzuf with that seed).
2. ‘test.doc’ is a valid document.
3. To generate a fuzzed document we feed a valid ‘test.doc’ to zzuf, and store a fuzzed document to ‘corrupted.doc’.
4. ‘-r’ option says to zzuf how much of the original document it should change.
5. Then, we feed fuzzed ‘corrupted.doc’ to AbiWord. We run AbiWord with ‘timeout’ command. It’s going to kill AbiWord process in two seconds if it didn’t finish by itself.
6. We use ‘–display’ option to ask AbiWord to use a virtual display. I also like to use AddressSanitizer whenever it’s possible because this great tool helps to detect more memory corruptions. I am usually not interested in memory leaks, so I pass ‘detect_leaks=0’ to ASAN_OPTIONS to disable memory leaks checker. I’ll show how AbiWord can be built with ASan later.
7. Finally, we redirect all AbiWord’s output to ‘log’ file, and look for ‘AddressSanitizer’ string in there. If we found the string, we stop fuzzing right away because it seems like we found a potential issue.

When the script stops with ‘Game over’ message we just need to look into logs to figure out what the problem is. It’s the most fun part. When the script stops, ‘corrupted.doc’ contains fuzzed data which caused the crash, so we can easily reproduce it. The script may be updated not to stop fuzzing if a crash was found. In this case, we need to store the corrupted file with different name, so that we can then use it to reproduce the crash.

# Use a watchdog script

zzuf is a very simple fuzzer. It just mutates input data randomly. There is a smarter fuzzer which probably everybody knows about. It is American fuzzy lop (AFL). This fuzzer is much smarter. It instruments an application before fuzzing to be able to get information about covered paths in it. Then, it uses this info generate new fuzzed data.

So, first you need to build your GUI application with AFL. In case of AbiWord, it can be done with the following commands:

```
./autogen.sh
CC="/home/artem/tools/afl/afl-gcc" \
CXX="/home/artem/tools/afl/afl-g++" \
AFL_USE_ASAN=1 \
    ./configure --prefix=/path/to/abiword/directory \
make
make install
```

Normally, you can run fuzzing with AFL with a command like the following:

```
afl-fuzz -m 1000 -t 10000+ -i in -o out \
    /path/to/abiword/directory/bin/abiword --display=:1 @@
```

But now you can’t use ‘timeout’ command. If you try the following command, then AFL will complain that you use non-instrumented binaries (and that’s actually true because we instrumented AbiWord, but not ‘timeout’):

```
afl-fuzz -m 1000 -t 10000+ -i in -o out \
    timeout 2s /path/to/abiword/directory/bin/abiword --display=:1 @@
```

So, we can’t use ‘timeout’ command anymore because we need to use instrumented binaries with AFL. There is another solution which may help here. We can run a watchdog script which is going to try to kill AbiWord window each second. It may be something simple like this:

```
#!/bin/bash

while true ; do
    sleep 1
    DISPLAY=:1 xdotool key alt+F4
done
```

Here we use ‘xdotool’ command to send ALT+F4 to AbiWord window on a virtual display.

Now we can run this script as a separate process, and then start fuzzing with ALF.

# How to build AbiWord with AddressSanitizer

I used the following commands to build AbiWord with ASan:

```
CFLAGS="-g -fsanitize=address -fno-omit-frame-pointer -O0" \
CPPFLAGS="-g -fsanitize=address -fno-omit-frame-pointer -O0" \
LDFLAGS="-fsanitize=address" \
    ./configure \
        --prefix=/path/to/abiword/directory \
        --disable-shared
make
make install
```

I have heard that now you can turn on ASan in AbiWord while configuring it with ‘–with-sanitizer=address’ option, but I have not tried it though.

# Discovered bugs in AbiWord

While fuzzing with AFL, I found a couple of bugs in AbiWord. They don’t look like security issues, but still better to fix them (at the moment of writing this post, most of them have been already fixed). Here is the list:

http://bugzilla.abisource.com/show_bug.cgi?id=13807: AbiWord crashes if –display option specified

http://bugzilla.abisource.com/show_bug.cgi?id=13826: Invalid memory access in IE_Imp_RTF::HandleStyleDefinition

http://bugzilla.abisource.com/show_bug.cgi?id=13827: _png_read() function can access pBytes array out of its bounds

http://bugzilla.abisource.com/show_bug.cgi?id=13828: Segmentation fault in fp_ContainerObject::getDocSectionLayout()

# Conclusion

There is still one problem with those two solutions above. The problem is that fuzzing is going to be very slow. Basically, one fuzzing iteration takes 1-2 seconds which is not very fast. On the other hand, GUI applications may take some time to start and render content of document. I didn’t measure how long AbiWord takes to start exactly, but I feel like it’s about 1 second on my old laptop. So, seems like it’s not possible to do better than one run per second on my hardware.

Any other ideas or comments are very welcome!