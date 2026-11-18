# 📖 The Nino Programming Language: Official Specification & Grammar Manual

> Author & Architect: **vvictor**  
> Official Authority: [ninosec.me](https://ninosec.me) | [github.com/jefmextra/nino-lang](https://github.com/jefmextra/nino-lang)

---

## 1. Lexical Structure & Tokens

Nino source files are encoded in **UTF-8** with extension `.nino`.

### Keywords
`fn`, `let`, `mut`, `if`, `else`, `while`, `for`, `in`, `step`, `guard`, `defer`, `match`, `with`, `return`, `sealed`, `morphic`, `transact`, `compensate`, `abort`, `require`, `ensure`, `and`, `or`, `not`, `true`, `false`, `nil`.

---

## 2. Variables & Mutability

By default, bindings declared with `let` are **immutable**:
```nino
let port = 8080
// port = 8081 // COMPILE ERROR: Cannot reassign immutable variable
```

To create a mutable variable, use `mut`:
```nino
mut counter = 0
counter = counter + 1
```

---

## 3. Pioneer Security Enclaves

### Sealed Zero-Leak Memory (`sealed`)
```nino
sealed let master_key = "RSA_PRIV_SECRET_89201"
// print(master_key)        // BLOCKED: Leak Guard prevents raw exposure
print(unseal(master_key))    // Explicit, audited exposure
```

### Morphic Memory Masking (`morphic`)
Variables declared `morphic mut` pair XOR-masked storage with runtime dynamic keys derived via `clock()` (`nino_morphic_read` / `nino_morphic_write`, intended as lightweight software obfuscation rather than hardware memory encryption):
```nino
morphic mut active_session_token = 94820
active_session_token = active_session_token + 100
```

---

## 4. Software Transactional Memory (`transact`)

```nino
mut balance = 1000

transact {
    balance = balance - 500
    guard verify_receiver() else {
        abort "Receiver signature invalid"
    }
} compensate {
    print("State automatically restored to 1000!")
}
```

---

## 5. Formal Contract Invariants (`require` & `ensure`)

```nino
fn allocate_buffer(size: i32) -> i32 {
    require(size > 0, "Buffer size must be positive")
    let allocated = size + 16
    ensure(allocated > size, "Allocation invariant failed")
    return allocated
}
```

---

## 6. Stream Pipeline Operator (`|>`)

```nino
"   vanguard core   " |> trim() |> uppercase() |> print()
```

---

## 7. Built-in Standard Library

### Math Intrinsics
`abs(x)`, `min(a, b)`, `max(a, b)`, `pow(a, b)`, `sqrt(x)`, `round(x)`

### String Intrinsics
`trim(s)`, `uppercase(s)`, `lowercase(s)`, `split(s, sep)`, `join(list, sep)`, `replace(s, old, new)`, `contains(s, sub)`

### System & Collections
`print(...)`, `clock()`, `sleep(s)`, `len(collection)`, `push(list, item)`, `pop(list)`, `sanitize(s)`, `version`, `unseal(secret)`

---

## 8. Custom Structs & Data Composite Types

```nino
struct Vector3 {
    mut x: f64,
    mut y: f64,
    mut z: f64
}

struct Player {
    name: string,
    mut health: i32,
    position: Vector3
}

let hero = Player {
    name: "Vanguard Titan",
    health: 100,
    position: Vector3 { x: 0.0, y: 10.0, z: 5.0 }
}

hero.health = 85
hero.position.x = 25.0
```

---

## 9. Low-Level Memory Buffers & Direct Hardware Access

```nino
// Allocate 64-byte raw RAM buffer
let vram = alloc_memory(64)

// Write raw bytes and 32-bit integers
write_byte(vram, 0, 0xDE)
write_i32(vram, 4, 1337)

let val = read_i32(vram, 4) // 1337

// Free memory with automatic zeroization and use-after-free protection
free_memory(vram)
```

---

## 10. Native File System I/O & Modular Imports

```nino
import "std/math"

file_write("output.txt", "High-performance native output")
let content = file_read("output.txt")
let exists = file_exists("output.txt")
file_delete("output.txt")
```

---

## 11. Foreign Function Interface (FFI)

Nino seamlessly links external dynamic C/Win32 shared libraries directly from source code:

```nino
// Declare dynamic foreign function from external DLL
extern fn Beep(dwFreq: i32, dwDuration: i32) -> i32 from "kernel32.dll"
extern fn GetTickCount() -> i32 from "kernel32.dll"

fn main() {
    let uptime = GetTickCount()
    print("Windows Uptime: {uptime} ms")
    Beep(750, 150)
}
```

---

## 12. Standard Library GUI & 3D Game Math

Nino features built-in high-performance standard libraries for game math and visual hardware canvas:

### 3D Linear Algebra (`std/math3d`)
```nino
import "std/math3d"

let v1 = vec3_new(1.0, 2.0, 3.0)
let v2 = vec3_new(4.0, 5.0, 6.0)

let dot_product = vec3_dot(v1, v2)
let cross_product = vec3_cross(v1, v2)
let unit_vector = vec3_normalize(v1)
```

### Native GUI Canvas Engine (`std/gui`)
```nino
import "std/gui"

let win = gui_create_window("Nino Game Canvas", 800, 600)
gui_draw_rect(win, 50, 50, 200, 100, "#38bdf8")
gui_draw_text(win, "Nino Real-Time Engine", 60, 80, 14, "#ffffff")
gui_refresh(win)
```

---

## 13. Freestanding Kernel Mode (`#no_std`)

Nino provides bare-metal x86_64 OS kernel compilation without standard C runtime libraries (`libc`):

```nino
#no_std

let COLOR_CYAN = 3
let COLOR_YELLOW = 14

fn kernel_main() {
    // Direct VGA Video Memory Manipulation at 0xB8000
    write_vga(0, 0, "=== NINO BARE-METAL KERNEL OS ===", COLOR_CYAN)
    write_vga(1, 0, "Target: x86_64 Freestanding Ring 0", COLOR_YELLOW)

    // Hardware Port I/O
    outb(0x3F8, 0x4E)

    // Low-Power CPU Halt Loop
    hlt()
}
```

Compile directly into a bare-metal kernel object:
```bash
nino build --freestanding examples/kernel_os.nino
```
Emits `examples/kernel_os.o` ready for multiboot and bootloader linkage.

