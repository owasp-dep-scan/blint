# Windows driver test fixture

A driver-shaped PE whose IOCTL surface is known ahead of time, used to check
blint's driver analysis against real compiler output rather than hand-written
assembly.

It exists because neither of the other test inputs can do that job. The unit
tests in `tests/test_driver_ioctl.py` feed in assembly a human wrote, which
proves the heuristics parse what we *think* compilers emit. The LOLDrivers
corpus (`contrib/loldrivers/`) publishes import lists rather than binaries, so it
cannot exercise anything that depends on disassembly at all.

| File | Purpose |
| --- | --- |
| `ioctl_driver.c` | The fixture source. Control codes are declared as `CTL_CODE` constants and dispatched through a compare chain, a jump-table switch and a data-section table. |
| `ntoskrnl.def` | Stub export list, turned into an import library so no WDK is needed. |
| `build.cmd` | Builds the `.sys` with MSVC from a VS x64 developer prompt. |
| `verify_recovery.py` | Runs blint over the built image and compares the recovered surface against the ground truth declared in the source. |
| `inbox_sweep.py` | False-positive sweep over the signed Microsoft drivers already present on a Windows machine. |

`.github/workflows/drivertests.yml` runs all of this: the fixture is built on a
Windows runner and analysed on a Linux runner, because nyxstone - and therefore
disassembly - is only installed there.

## Building and checking locally

On Windows, from a Visual Studio x64 developer command prompt:

```cmd
contrib\win-driver-fixture\build.cmd blint_test_driver.sys
python contrib\win-driver-fixture\verify_recovery.py blint_test_driver.sys
```

Any toolchain that emits a PE works, which is useful for checking a second
compiler's code generation. With clang and lld, from any host:

```bash
llvm-dlltool -d ntoskrnl.def -l ntoskrnl.lib -m i386:x86-64
clang --target=x86_64-pc-windows-msvc -O2 -fshort-wchar -c ioctl_driver.c -o ioctl_driver.obj
lld-link /subsystem:native /driver /entry:DriverEntry /nodefaultlib \
    /out:blint_test_driver.sys ioctl_driver.obj ntoskrnl.lib
```

Building with a second compiler is worth doing. Two of the recovery rules exist
because clang lowers dispatch differently from MSVC: it folds the switch base
into `lea eax, [rcx + <two's complement>]` instead of `sub`, and it emits a
binary search whose pivots are one below a real control code.

## The fixture is never loaded

This is a driver with an unguarded physical-memory primitive and no security
descriptor - loading it would be a real local privilege escalation. It is built
to be read by a static analyser and nothing else. `DriverEntry` is never
executed, and nothing here installs or starts a service.
