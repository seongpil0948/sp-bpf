# C 언어 & eBPF 문법 가이드 (Go 개발자용)

이 문서는 Go 경험이 있는 개발자가 이 eBPF 프로젝트의 C 코드를 이해하는 데 필요한 핵심 개념들을 정리합니다.

## 📁 파일 구조 이해하기

### `.h` 파일 (헤더 파일)
- **역할**: 함수 선언, 매크로 정의, 타입 정의를 포함
- **Go와 비교**: Go의 interface나 type 정의를 별도 파일로 분리한 것과 유사
- **이 프로젝트**: `hello.bpf.h` - eBPF 프로그램에서 사용할 공통 정의

### `.c` 파일 (소스 파일)
- **역할**: 실제 함수 구현과 실행 로직
- **Go와 비교**: Go의 `.go` 파일과 동일한 역할
- **이 프로젝트**: `hello.bpf.c` - eBPF 프로그램의 실제 구현

### `.o` 파일 (오브젝트 파일)
- **역할**: 컴파일된 바이너리 파일
- **Go와 비교**: `go build`로 생성되는 실행 파일과 유사하지만 중간 단계
- **이 프로젝트**: `hello.bpf.o` - 커널에 로드될 eBPF 바이트코드

---

## 🔧 C 언어 핵심 문법

### 1. 전처리기 (Preprocessor)

#### `#include`
```c
#include <linux/types.h>  // 시스템 헤더 (표준 라이브러리)
#include "hello.bpf.h"     // 사용자 정의 헤더 (같은 디렉토리)
```
- **Go와 비교**: `import` 문과 유사
- **차이점**: 
  - `<>`: 시스템 경로에서 검색 (Go의 표준 라이브러리)
  - `""`: 현재 디렉토리에서 검색 (Go의 로컬 패키지)

#### `#define` (매크로)
```c
#define BPF_HASH(_name, _key_type, _value_type) \
    BPF_MAP(_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, 10240);
```
- **역할**: 코드 치환 (텍스트 대체)
- **Go와 비교**: Go에는 없는 기능. const나 함수로 구현해야 함
- **주의**: 컴파일 전에 텍스트로 치환되므로 타입 체크가 없음
- **백슬래시(`\`)**: 여러 줄로 매크로를 작성할 때 사용

#### `#ifdef`, `#undef`
```c
#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif
```
- **역할**: 조건부 컴파일
- **Go와 비교**: build tags (`// +build`)와 유사하지만 더 세밀한 제어
- `#ifdef`: "만약 정의되어 있다면"
- `#undef`: 기존 정의 제거
- `#endif`: 조건문 종료

### 2. 타입 시스템

#### typedef
```c
typedef __u64 u64;
```
- **역할**: 기존 타입에 새로운 이름 부여
- **Go와 비교**: `type u64 = __u64` (type alias)

#### 구조체 (struct)
```c
struct bpf_map_def {
    .type = _type,
    .key_size = sizeof(_key_type),
    .value_size = sizeof(_value_type),
    .max_entries = _max_entries,
};
```
- **Go와 비교**: Go의 struct와 거의 동일
- **차이점**: 
  - C는 `.`으로 필드 초기화 (designated initializer)
  - Go는 `FieldName: value` 형식

#### 포인터
```c
int hello(void *ctx)
bpf_perf_event_output(ctx, &events, ...)
```
- `*`: 포인터 선언 또는 역참조
- `&`: 주소 연산자
- **Go와 비교**: Go도 포인터가 있지만 C는 더 많이 사용
- `void *`: 어떤 타입이든 가리킬 수 있는 포인터 (Go의 `interface{}`와 유사)

### 3. 함수 선언

```c
int hello(void *ctx)
{
    bpf_printk("I'm alive!");
    return 0;
}
```
- **형식**: `반환타입 함수명(매개변수타입 매개변수명)`
- **Go와 비교**: 
  ```go
  func hello(ctx *void) int {
      // ...
      return 0
  }
  ```
- **차이점**: C는 타입이 변수명 앞에 옴

### 4. 배열
```c
char data[100];
char LICENSE[] = "Dual BSD/GPL";
```
- `char data[100]`: 크기 100인 char 배열 선언
- `char LICENSE[]`: 컴파일러가 크기 자동 계산
- **Go와 비교**: 
  ```go
  var data [100]byte
  var LICENSE = []byte("Dual BSD/GPL")
  ```

---

## 🎯 eBPF 특화 문법

### SEC (Section)
```c
SEC("kprobe/sys_execve")
int hello(void *ctx)
```
- **역할**: eBPF 프로그램을 특정 섹션에 배치
- **의미**: 이 함수가 어떤 커널 이벤트에 연결될지 지정
- `kprobe/sys_execve`: execve 시스템콜이 호출될 때 실행
- `raw_tracepoint/sys_enter`: 모든 시스템콜 진입 시 실행

### BPF 헬퍼 함수

커널이 제공하는 eBPF 전용 함수들입니다. 일반 C 함수와 달리 커널 컨텍스트에서만 동작합니다.

#### 1. bpf_printk()
```c
bpf_printk("I'm alive!");
bpf_printk("PID: %d, comm: %s", pid, comm);
```
- **역할**: 디버깅용 로그 출력
- **출력 위치**: `/sys/kernel/debug/tracing/trace_pipe`
- **Go와 비교**: `fmt.Printf()`와 유사하지만 커널 로그로 출력
- **제한사항**: 최대 3개의 인자만 가능, 성능 오버헤드 있음

#### 2. bpf_get_current_comm()
```c
char comm[16];
bpf_get_current_comm(&comm, sizeof(comm));
```
- **역할**: 현재 프로세스의 이름(command) 가져오기
- **매개변수**:
  - `&comm`: 데이터를 저장할 버퍼의 포인터
  - `sizeof(comm)`: 버퍼 크기
- **반환값**: 성공 시 0, 실패 시 음수
- **Go와 비교**: `os.Args[0]`와 유사

#### 3. bpf_perf_event_output()
```c
bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, 100);
```
- **역할**: 데이터를 userspace(Go)로 전송
- **매개변수**:
  - `ctx`: eBPF 프로그램의 컨텍스트
  - `&events`: perf event 배열 맵의 포인터
  - `BPF_F_CURRENT_CPU`: 현재 CPU의 버퍼 사용 (플래그)
  - `&data`: 전송할 데이터의 포인터
  - `100`: 전송할 데이터 크기 (바이트)
- **Go와 비교**: Go 채널에 데이터 전송하는 것과 유사
  ```go
  // Go에서 수신
  e := make(chan []byte, 300)
  p, err := bpfModule.InitPerfBuf("events", e, nil, 1024)
  
  for data := range e {
      // C에서 보낸 데이터 처리
      fmt.Println(string(data))
  }
  ```

#### 4. 기타 유용한 BPF 헬퍼 함수들

```c
// 현재 프로세스 ID 가져오기
u32 pid = bpf_get_current_pid_tgid() >> 32;
u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

// 현재 사용자 ID 가져오기
u32 uid = bpf_get_current_uid_gid() >> 32;

// 현재 시간 (나노초)
u64 ts = bpf_ktime_get_ns();

// 맵에서 값 읽기
void *value = bpf_map_lookup_elem(&my_map, &key);

// 맵에 값 쓰기
bpf_map_update_elem(&my_map, &key, &value, BPF_ANY);

// 맵에서 값 삭제
bpf_map_delete_elem(&my_map, &key);
```

### BPF Perf Event 메커니즘

`bpf_perf_event_output()`의 작동 방식을 자세히 이해하기:

```
┌─────────────────────────────────────────────────────────────┐
│ Kernel Space (eBPF)                                         │
│                                                              │
│  ┌──────────────────────────────────────┐                  │
│  │ eBPF 프로그램                          │                  │
│  │                                      │                  │
│  │  char data[100];                    │                  │
│  │  bpf_get_current_comm(&data, 100);  │                  │
│  │                                      │                  │
│  │  bpf_perf_event_output(             │                  │
│  │      ctx,                            │                  │
│  │      &events,  ─────────────┐       │                  │
│  │      BPF_F_CURRENT_CPU,     │       │                  │
│  │      &data,                 │       │                  │
│  │      100                    │       │                  │
│  │  );                         │       │                  │
│  └─────────────────────────────┼───────┘                  │
│                                 │                           │
│  ┌──────────────────────────────▼──────┐                  │
│  │ BPF_MAP_TYPE_PERF_EVENT_ARRAY       │                  │
│  │                                      │                  │
│  │  [CPU 0 ring buffer]                │                  │
│  │  [CPU 1 ring buffer]                │                  │
│  │  [CPU 2 ring buffer]                │                  │
│  │  [CPU 3 ring buffer]                │                  │
│  └──────────────────┬───────────────────┘                  │
│                     │                                       │
└─────────────────────┼───────────────────────────────────────┘
                      │ Perf Ring Buffer
                      │ (메모리 공유 영역)
┌─────────────────────▼───────────────────────────────────────┐
│ User Space (Go)                                             │
│                                                              │
│  ┌──────────────────────────────────────┐                  │
│  │ Go 프로그램                            │                  │
│  │                                      │                  │
│  │  e := make(chan []byte, 300)        │                  │
│  │                                      │                  │
│  │  p, _ := bpfModule.InitPerfBuf(     │                  │
│  │      "events",  ◄────────────────┐  │                  │
│  │      e,                           │  │                  │
│  │      nil,                         │  │                  │
│  │      1024                         │  │                  │
│  │  )                                │  │                  │
│  │                                   │  │                  │
│  │  p.Start()                        │  │                  │
│  │                                   │  │                  │
│  │  for data := range e {            │  │                  │
│  │      comm := string(data)         │  │                  │
│  │      counter[comm]++              │  │                  │
│  │  }                                │  │                  │
│  └───────────────────────────────────┘  │                  │
│                                          │                  │
│         libbpfgo PerfBuffer 폴링 메커니즘                   │
│                                          │                  │
└──────────────────────────────────────────────────────────────┘
```

**동작 순서:**

1. **C (eBPF)**: `bpf_perf_event_output()`로 데이터 전송
2. **Kernel**: CPU별 ring buffer에 데이터 저장
3. **libbpfgo**: ring buffer를 주기적으로 폴링
4. **Go**: 채널로 데이터 수신

**왜 이 구조를 사용할까?**
- **Zero-copy**: 메모리 복사 최소화
- **Lock-free**: CPU별 버퍼로 동시성 문제 해결
- **고성능**: 대량의 이벤트를 빠르게 전송 가능

**Go와 비교:**
```go
// 일반 Go 채널 (단일 버퍼)
ch := make(chan string, 100)
ch <- "data"

// eBPF Perf Buffer (CPU별 링 버퍼)
// - 각 CPU마다 독립적인 버퍼
// - 커널-유저 공간 메모리 공유
// - 훨씬 더 빠름!
```

### 매크로 사용 예시

#### BPF_PERF_OUTPUT 매크로
```c
BPF_PERF_OUTPUT(events)
```

**전처리 전 (hello.bpf.h에서 정의):**
```c
#define BPF_PERF_OUTPUT(_name) \
    BPF_MAP(_name, BPF_MAP_TYPE_PERF_EVENT_ARRAY, int, __u32, 1024);
```

**전처리 후 확장됨:**
```c
struct bpf_map_def SEC("maps") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(__u32),
    .max_entries = 1024,
};
```

**각 필드의 의미:**
- `type`: 맵 타입 - Perf Event 배열
- `key_size`: 키 크기 - CPU 번호 (int)
- `value_size`: 값 크기 - 이벤트 파일 디스크립터
- `max_entries`: 최대 항목 수 - CPU 개수 (1024개까지)

**Go에서 사용:**
```go
// "events"라는 이름으로 맵 찾기
p, err := bpfModule.InitPerfBuf("events", e, nil, 1024)
```

#### BPF_HASH 매크로
```c
BPF_HASH(my_map, u32, u64)
```

**전처리 후:**
```c
struct bpf_map_def SEC("maps") my_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),      // 4 bytes
    .value_size = sizeof(u64),    // 8 bytes
    .max_entries = 10240,
};
```

**사용 예시:**
```c
// C 코드에서
u32 key = 123;
u64 value = 456;
bpf_map_update_elem(&my_map, &key, &value, BPF_ANY);

// 값 읽기
u64 *val = bpf_map_lookup_elem(&my_map, &key);
if (val) {
    bpf_printk("Value: %llu", *val);
}
```

```go
// Go 코드에서
myMap, err := bpfModule.GetMap("my_map")
if err != nil {
    panic(err)
}

key := uint32(123)
value := uint64(456)
err = myMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&value))
```

#### 매크로 vs Go 상수

**C 매크로:**
```c
#define MAX_ENTRIES 10240
#define TASK_COMM_LEN 16
```
- 컴파일 전에 텍스트 치환
- 타입 검사 없음
- 디버깅 어려움

**Go 상수:**
```go
const MaxEntries = 10240
const TaskCommLen = 16
```
- 타입 안정성
- 디버깅 쉬움
- 런타임 오버헤드 없음

**왜 C에서 매크로를 많이 쓸까?**
- 역사적 이유 (C89에는 const가 배열 크기로 못 씀)
- 타입 제네릭처럼 사용 가능
- 조건부 컴파일 가능

---

## 🔄 C와 Go 간의 데이터 흐름

### 1. 컴파일 단계
```
hello.bpf.c → (clang) → hello.bpf.o
```
- C 코드를 eBPF 바이트코드로 컴파일

### 2. Go에서 로드
```go
bpfModule, err := bpf.NewModuleFromFile("hello.bpf.o")
```
- 컴파일된 .o 파일을 Go 프로그램이 런타임에 읽어서 커널에 로드

### 3. 데이터 전달
```c
// C 코드: 데이터를 events 맵으로 전송
char data[100];
bpf_get_current_comm(&data, 100);
bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, 100);
```

```go
// Go 코드: events 맵에서 데이터 수신
e := make(chan []byte, 300)
p, err := bpfModule.InitPerfBuf("events", e, nil, 1024)
p.Start()

for data := range e {
    comm := string(data)  // C의 char[] → Go의 string
    counter[comm]++
}
```

---

## 📚 자주 보는 패턴

### 1. sizeof 연산자
```c
.key_size = sizeof(_key_type)
```
- **역할**: 타입이나 변수의 바이트 크기 반환
- **Go와 비교**: `unsafe.Sizeof()`와 유사하지만 C에서 더 자주 사용

### 2. 빌드 태그
```c
// +build ignore
```
- **역할**: Go 컴파일러가 이 파일을 무시하도록 지시
- C 파일이지만 Go 프로젝트에 포함되어 있어서 필요

### 3. Cgo import
```go
import (
	"C"
	bpf "github.com/aquasecurity/tracee/libbpfgo"
)
```
- `import "C"`: Cgo를 사용하여 C 라이브러리와 연동
- 이를 통해 Go에서 libbpf C 라이브러리를 사용 가능

---

## 💡 코드 읽기 팁

### C 코드를 읽을 때
1. **헤더 파일부터 읽기**: 매크로와 타입 정의 이해
2. **전처리기 추적**: `#define` 매크로가 어떻게 확장되는지 머릿속으로 치환
3. **포인터 주의**: `*`와 `&`가 무엇을 가리키는지 확인
4. **eBPF 섹션 파악**: `SEC()`로 언제 실행되는지 확인

### Go-C 연동 이해하기
1. C 코드는 **컴파일 타임**에 `.o` 파일로 변환
2. Go 코드는 **런타임**에 `.o` 파일을 로드
3. 데이터는 **eBPF 맵**(map)을 통해 C ↔ Go 간 전달

---

## 🎓 학습 순서 추천

1. ✅ `hello.bpf.h` 읽기 - 매크로가 무엇을 정의하는지 이해
2. ✅ `hello.bpf.c` 읽기 - 실제 eBPF 프로그램 로직 파악
3. ✅ `hello.go` 읽기 - Go에서 어떻게 C 코드를 로드하고 사용하는지
4. ✅ `Makefile` 읽기 - 빌드 과정 이해

---

---

## 🛠️ 개발 도구 및 명령어

### readelf - ELF 파일 분석 도구

`readelf`는 컴파일된 바이너리 파일의 내부 구조를 확인하는 리눅스 유틸리티입니다.

#### ELF (Executable and Linkable Format)란?
- 리눅스/유닉스의 표준 실행 파일 형식
- 실행 파일, 오브젝트 파일(`.o`), 공유 라이브러리(`.so`) 등에 사용
- **Go와 비교**: Go로 빌드한 바이너리도 리눅스에서는 ELF 형식

#### 이 프로젝트에서 readelf 사용하기

```bash
# 컴파일 후
make all

# hello.bpf.o 파일 분석
readelf -a hello.bpf.o
```

**주요 옵션:**
```bash
# 파일 헤더 정보 보기
readelf -h hello.bpf.o

# 섹션 헤더 목록 보기 (가장 유용!)
readelf -S hello.bpf.o

# 심볼 테이블 보기
readelf -s hello.bpf.o

# 모든 정보 보기
readelf -a hello.bpf.o
```

#### readelf로 볼 수 있는 것들

**1. 섹션 (Sections)**
```
Section Headers:
  [Nr] Name              Type
  [ 1] .text             PROGBITS
  [ 2] kprobe/sys_execve PROGBITS    <- eBPF 프로그램
  [ 3] raw_tracepoint/sys_enter      <- 또 다른 eBPF 프로그램
  [ 4] maps              PROGBITS    <- eBPF 맵 정의
  [ 5] license           PROGBITS    <- 라이선스 정보
```

**2. 심볼 (Symbols)**
```
Symbol table '.symtab':
  Num:    Value  Size Type    Bind   Vis      Ndx Name
   42: 00000000    48 FUNC    GLOBAL DEFAULT    2 hello
   43: 00000000   128 FUNC    GLOBAL DEFAULT    3 hello_bpftrace
   44: 00000000   100 OBJECT  GLOBAL DEFAULT    4 events
```

**3. 프로그램 헤더**
- eBPF의 경우 섹션 정보가 중요
- 각 `SEC()` 매크로가 어떤 섹션을 만드는지 확인 가능

#### 실전 예시

```bash
# 섹션 목록만 간단히 보기
readelf -S hello.bpf.o | grep -E "kprobe|tracepoint|maps"

# 출력:
#   [ 2] kprobe/sys_execve
#   [ 3] raw_tracepoint/sys_enter
#   [ 4] maps
```

이렇게 확인한 섹션 이름을 Go 코드에서 사용:
```go
// Go 코드에서 "hello" 프로그램을 가져옴
// -> readelf에서 본 kprobe/sys_execve 섹션에 정의된 함수
prog, err := bpfModule.GetProgram("hello")

// "events" 맵을 가져옴
// -> readelf에서 본 maps 섹션에 정의된 맵
p, err := bpfModule.InitPerfBuf("events", e, nil, 1024)
```

### objdump - 디스어셈블러

`objdump`는 오브젝트 파일의 어셈블리 코드를 보여줍니다.

```bash
# eBPF 바이트코드 보기
objdump -d hello.bpf.o

# 특정 섹션만 보기
objdump -d -j kprobe/sys_execve hello.bpf.o
```

**출력 예시:**
```assembly
Disassembly of section kprobe/sys_execve:

0000000000000000 <hello>:
       0:       b7 01 00 00 0a 00 00 00 r1 = 10
       1:       6b 1a fc ff 00 00 00 00 *(u16 *)(r10 - 4) = r1
       ...
```

### llvm-objdump (eBPF 전용)

eBPF 바이트코드를 더 읽기 쉽게 보여줍니다:
```bash
llvm-objdump -d hello.bpf.o
```

---

## 📦 빌드 프로세스 이해하기

### Makefile 분석

```makefile
# 아키텍처 감지 (x86_64, arm64 등)
ARCH=$(shell uname -m)

# 타겟 파일들
TARGET := hello              # Go 실행 파일
TARGET_BPF := hello.bpf.o    # eBPF 오브젝트 파일

# 빌드 명령
all: $(TARGET) $(TARGET_BPF)
```

#### 1단계: eBPF C 코드 컴파일
```makefile
$(TARGET_BPF): $(BPF_SRC)
	clang \
		-I /usr/include/$(ARCH)-linux-gnu \
		-O2 -c -target bpf \
		-o $@ $<
```

**옵션 설명:**
- `-I`: 헤더 파일 검색 경로 추가
- `-O2`: 최적화 레벨 2 (성능 향상)
- `-c`: 컴파일만 하고 링크는 하지 않음 (`.o` 파일 생성)
- `-target bpf`: eBPF 바이트코드로 컴파일
- `-o $@`: 출력 파일 (`hello.bpf.o`)
- `$<`: 입력 파일 (`hello.bpf.c`)

**Go와 비교:**
```bash
# Go의 경우
go build -o hello *.go
```

#### 2단계: Go 코드 컴파일
```makefile
go_env := CC=clang CGO_CFLAGS="-I $(LIBBPF_HEADERS)" CGO_LDFLAGS="$(LIBBPF_OBJ)"
$(TARGET): $(GO_SRC)
	$(go_env) go build -o $(TARGET)
```

**환경 변수 설명:**
- `CC=clang`: C 컴파일러로 clang 사용 (Cgo용)
- `CGO_CFLAGS`: C 코드 컴파일 시 헤더 경로 지정
- `CGO_LDFLAGS`: 링킹 시 libbpf 라이브러리 경로 지정

### 전체 빌드 플로우

```
hello.bpf.c  ──[clang]──>  hello.bpf.o  ──[런타임에 Go가 로드]──>  커널
                             │
                             │
hello.go  ───[go build]───>  hello (실행 파일)
   │                           │
   └──[Cgo]──> libbpf ────────┘
```

### 의존성 패키지

```bash
sudo apt-get install libbpf-dev make clang llvm libelf-dev
```

**각 패키지의 역할:**
- `libbpf-dev`: eBPF 프로그램을 로드하고 관리하는 C 라이브러리
- `make`: Makefile 실행 도구
- `clang`: C 코드를 eBPF 바이트코드로 컴파일
- `llvm`: clang의 백엔드, eBPF 코드 생성
- `libelf-dev`: ELF 파일 파싱 라이브러리

---

## 🔍 디버깅 팁

### 1. eBPF 프로그램이 로드되는지 확인
```bash
# 로드된 eBPF 프로그램 목록
sudo bpftool prog list

# 특정 프로그램 상세 정보
sudo bpftool prog show id <ID>

# 프로그램 덤프 (바이트코드)
sudo bpftool prog dump xlated id <ID>
```

### 2. eBPF 맵 확인
```bash
# 로드된 맵 목록
sudo bpftool map list

# 맵 내용 보기
sudo bpftool map dump id <ID>
```

### 3. 커널 로그 확인
```bash
# bpf_printk() 출력 보기
sudo cat /sys/kernel/debug/tracing/trace_pipe

# 또는 Go 코드에서
bpf.TracePrint()  // 별도 고루틴에서 실행
```

### 4. 컴파일 오류 디버깅
```bash
# verbose 모드로 컴파일
clang -v -I /usr/include/x86_64-linux-gnu -O2 -c -target bpf -o hello.bpf.o hello.bpf.c

# 전처리 결과만 보기 (매크로 확장 확인)
clang -E hello.bpf.c
```

### 5. Go 런타임 오류 디버깅
```go
// 상세한 에러 출력
if err != nil {
    fmt.Printf("Error: %+v\n", err)
    panic(err)
}
```

---

## 🚀 실행 가이드

### 기본 실행
```bash
# 1. 빌드
make all

# 2. 실행 (root 권한 필요)
sudo ./hello

# 3. 다른 터미널에서 시스템콜 발생시키기
ls  # execve 시스템콜 발생
cat /etc/passwd  # sys_enter 이벤트 발생

# 4. Ctrl+C로 종료하면 카운터 출력
```

### Docker 사용
```bash
# 1. 이미지 빌드
docker build -t hello .

# 2. 컴파일
docker run --rm -v $(pwd)/:/app/:z hello

# 3. 실행 (호스트 커널 접근 필요)
sudo ./hello
```

### macOS에서 개발하기
```bash
# macOS는 eBPF를 지원하지 않으므로
# Linux VM이나 Docker를 사용해야 함

# Lima를 사용한 Linux VM
brew install lima
limactl start
limactl shell default

# 또는 Multipass
brew install multipass
multipass launch --name ebpf-dev
multipass shell ebpf-dev
```

---

## 📊 프로그램 동작 원리

### hello 함수 (kprobe)
```c
SEC("kprobe/sys_execve")
int hello(void *ctx)
{
    bpf_printk("I'm alive!");
    return 0;
}
```

**동작:**
1. `execve` 시스템콜이 호출될 때마다 실행
2. 커널 로그에 "I'm alive!" 출력
3. `sudo cat /sys/kernel/debug/tracing/trace_pipe`로 확인 가능

### hello_bpftrace 함수 (raw_tracepoint)
```c
SEC("raw_tracepoint/sys_enter")
int hello_bpftrace(void *ctx)
{
    char data[100];
    bpf_get_current_comm(&data, 100);  // 프로세스 이름 가져오기
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, 100);
    return 0;
}
```

**동작:**
1. 모든 시스템콜 진입 시 실행
2. 현재 프로세스 이름(command)을 가져옴
3. `events` 맵을 통해 Go 프로그램으로 전송
4. Go에서 프로세스별 시스템콜 카운트

### Go에서 데이터 수신
```go
// 채널 생성
e := make(chan []byte, 300)

// Perf 버퍼 초기화
p, err := bpfModule.InitPerfBuf("events", e, nil, 1024)
p.Start()

// 카운터
counter := make(map[string]int, 350)
go func() {
    for data := range e {
        comm := string(data)  // 프로세스 이름
        counter[comm]++       // 카운트 증가
    }
}()

// 종료 시 결과 출력
<-sig
p.Stop()
for comm, n := range counter {
    fmt.Printf("%s: %d\n", comm, n)
}
```

**출력 예시:**
```
bash: 45
systemd: 12
Chrome: 234
...
```

---

## 🔗 참고 자료

- [C 전처리기 문법](https://en.cppreference.com/w/c/preprocessor)
- [eBPF 헬퍼 함수 목록](https://man7.org/linux/man-pages/man7/bpf-helpers.7.html)
- [libbpfgo 문서](https://github.com/aquasecurity/tracee/tree/main/libbpfgo)
- [ELF 파일 형식](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)
- [bpftool 매뉴얼](https://man7.org/linux/man-pages/man8/bpftool.8.html)
- [eBPF 공식 문서](https://ebpf.io/)

---

**이 문서로 프로젝트의 전체 워크플로우를 완벽히 이해할 수 있습니다!** 🚀
