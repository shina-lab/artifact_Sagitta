#include "polytracker/polytracker.h"
#include "polytracker/early_construct.h"
#include "polytracker/taint_sources.h"
#include "taintdag/fnmapping.h"
#include "taintdag/polytracker.h"
#include <sanitizer/dfsan_interface.h>

#include <atomic>
#include <inttypes.h>
#include <iostream>
#include <string_view>

EARLY_CONSTRUCT_EXTERN_GETTER(taintdag::PolyTracker, polytracker_tdag);
static bool log_untainted_labels_mode = false;

static std::atomic_flag polytracker_init_flag = ATOMIC_FLAG_INIT;
static FILE* polytracker_label_log_file = NULL;
#define POLYLOG_FD 100

// NOTE: polytracker は正常終了時にtdagを保存する。
//       異常終了する場合でも途中で保存するワークアラウンドを実施する
__attribute__((destructor))
extern "C" void __polytracker_save() {
  get_polytracker_tdag().save();
}

static bool polytracker_is_initialized() {
  return polytracker_init_flag.test(std::memory_order_relaxed);
}

static void polytracker_initialize() {
  polytracker_init_flag.test_and_set(std::memory_order_relaxed);
  std::atexit(__polytracker_save);
}

extern "C" taintdag::Functions::index_t
__polytracker_log_func_entry(char *name, uint16_t len) {
  if (!polytracker_is_initialized()) {
    return 0;
  }
  return get_polytracker_tdag().function_entry({name, len});
}

extern "C" void
__polytracker_log_func_exit(taintdag::Functions::index_t func_index) {
  if (!polytracker_is_initialized()) {
    return;
  }
  get_polytracker_tdag().function_exit(func_index);
}

extern "C" dfsan_label __polytracker_union_table(const dfsan_label &l1,
                                                 const dfsan_label &l2) {
  if (!polytracker_is_initialized()) {
    return 0;
  }
  return get_polytracker_tdag().union_labels(l1, l2);
}

extern "C" void __polytracker_log_conditional_branch(dfsan_label label) {
  if (!polytracker_is_initialized()) {
    return;
  }

  if (label > 0) {
    // get_polytracker_tdag().affects_control_flow(label);
  }
}

extern "C" void
__dfsw___polytracker_log_conditional_branch(uint64_t conditional,
                                            dfsan_label conditional_label) {
  if (!polytracker_is_initialized()) {
    return;
  }
  __polytracker_log_conditional_branch(conditional_label);
}

extern "C" void
__polytracker_log_label(
  dfsan_label label, char* opcode, char *path, uint64_t line, uint64_t column, char* function) {
  if (!polytracker_is_initialized()) {
    return;
  }

  if (polytracker_label_log_file == NULL) {
    printf("Cannot open label log file.\n");
    return;
  }
  if (label > 0 || log_untainted_labels_mode || std::string_view(function) == "tls_get_ticket_from_client") {
    fprintf(
      polytracker_label_log_file, 
      "- { kind: label, label: %d, opcode: %s, path: %s, line: %lu, column: %lu, function: %s }\n", 
      label, opcode, path, line, column, function
    );
  }
  fflush(polytracker_label_log_file);
}

extern "C" void
__dfsw___polytracker_log_label(uint32_t _val, char* opcode, char *path, uint64_t line, uint64_t column, char* function,
                               dfsan_label val_label /* rest of params are omitted */) {
  if (!polytracker_is_initialized()) {
    return;
  }
  __polytracker_log_label(val_label, opcode, path, line, column, function);
}

extern "C" void
__polytracker_log_label_ptr(
  dfsan_label label, char* opcode, char *path, uint64_t line, uint64_t column, char* function) {
    __polytracker_log_label(label, opcode, path, line, column, function);
}

extern "C" void
__dfsw___polytracker_log_label_ptr(void* ptr, char* opcode, char *path, uint64_t line, uint64_t column, char* function
                                   /* Ignore taint label */) {
  if (!polytracker_is_initialized()) {
    return;
  }
  // NOTE: DFSan may passes old taint label when new label has given. So we need to get label from ptr.
  // e.g. int* ptr = malloc(sizeof(int)); ptr[0] = 1; int a = ptr[0];
  //           ~~~                        ~~~                 ~~~
  //           label 1                    label 2             label 1
  // if (log_untainted_labels_mode) {
  //   fprintf(stderr, "[*] __dfsw___polytracker_log_label_ptr: dfsan_read_label(ptr=%p, sizeof(uint8_t))", ptr); // DEBUG: 
  // }
  if (!ptr) {
    // if (log_untainted_labels_mode) {
    //   fprintf(stderr, "=(Failed)\n"); // DEBUG: 
    // }
    return;
  }

  dfsan_label label = dfsan_read_label(ptr, sizeof(uint8_t));
  __polytracker_log_label(label, opcode, path, line, column, function);
  // if (log_untainted_labels_mode) {
  //   fprintf(stderr, "=%d\n", label); // DEBUG: 
  // }
}

extern "C" dfsan_label
__polytracker_taint_store(void *addr, uint64_t value, uint64_t size, char *path, uint64_t line, uint64_t column, char* function,
                                 dfsan_label _addr_label, dfsan_label value_label, dfsan_label *ret_label) {
  dfsan_label dest_label = dfsan_read_label(addr, sizeof(uint8_t));
  // if (log_untainted_labels_mode) {
  //   fprintf(stderr, "[*] __polytracker_taint_store: dfsan_read_label(addr=%p, sizeof(uint8_t))=%d\n", addr, dest_label); // DEBUG: 
  // }
  if (dest_label > 0 /* dest is tainted */ && value_label == 0 /* src is not tainted */) {
    if (std::string_view(path).starts_with("/cxx_lib")) {
      // Do not create taint source in C++ library
      return dest_label;
    }

    // NOTE: テイントタグの節約のため、古いテイントタグを使う
    dfsan_set_label(dest_label, addr, size);
    __polytracker_log_label(dest_label, (char *) "store", path, line, column, function);
    return dest_label;

    // // store(*0x0000000000000000=0x0000000000000000,size=00)
    // char name[53] = {};
    // snprintf(name, sizeof(name), "store(*%p=%#lx,size=%ld)", addr, value, size);

    // auto rng = get_polytracker_tdag().create_taint_source(
    //   name, {reinterpret_cast<uint8_t *>(addr), size});
    // if (rng) {
    //   dprintf(POLYLOG_FD, "[*] Create taint source by store: address=%p, size=%ld, label=%d:%d\n", addr, size, rng->first, rng->second); // DEBUG: 
    //   fprintf(
    //     polytracker_label_log_file, 
    //     "- { kind: update, cause: store, old_label: %d, new_label: %d, path: %s, line: %lu, column: %lu, function: %s }\n", 
    //     dest_label, rng->first, path, line, column, function
    //   );
    //   return rng->first;
    // } else {
    //   dprintf(POLYLOG_FD, "[!] Failed to create taint source for store: address=%p, size=%ld\n", addr, size); // DEBUG: 
    // }
  }
  __polytracker_log_label(value_label, (char *) "store", path, line, column, function);
  if (value_label > 0) {
    *ret_label = value_label;
  }
  return 0; // not to call dfsan_set_label()
}

extern "C" dfsan_label
__dfsw___polytracker_taint_store(void *addr, uint64_t value, uint64_t size, char *path, uint64_t line, uint64_t column, char* function,
                                 dfsan_label addr_label, dfsan_label value_label, dfsan_label _size_label, dfsan_label _path_label, dfsan_label _line_label, dfsan_label _column_label, dfsan_label _function_label, dfsan_label *ret_label) {
  if (!polytracker_is_initialized()) {
    return 0;
  }
  return __polytracker_taint_store(addr, value, size, path, line, column, function, addr_label, value_label, ret_label);
}

extern "C" dfsan_label
__polytracker_taint_alloca(void *addr, uint64_t size, char* function) {
  // alloca されたメモリは原則テイントを消去する
  if (log_untainted_labels_mode) {
    fprintf(
      stderr, "[*] Remove existing taint label by alloca: address=%p, size=%ld, label=%d\n",
      addr, size, dfsan_read_label(addr, sizeof(uint8_t))
    ); // DEBUG: 
  }
  dfsan_set_label(0, addr, size);

  // NOTE: alloca までテイントソースとして扱うとタグの数が不足しやすいので注意
  if (size <= 8) {
    return 0;
  }

  // alloca(0x0000000000000000,size=0000)
  char name[37] = {};
  snprintf(name, sizeof(name), "alloca(%p,size=%ld)", addr, size);

  auto rng = get_polytracker_tdag().create_taint_source(
    name, {reinterpret_cast<uint8_t *>(addr), size});
  if (rng) {
    dprintf(POLYLOG_FD, "[*] Create taint source by alloca: address=%p, size=%ld, label=%d:%d\n", addr, size, rng->first, rng->second); // DEBUG: 
    return rng->first;
  } else {
    dprintf(POLYLOG_FD, "[!] Failed to create taint source for alloca: address=%p, size=%ld\n", addr, size); // DEBUG: 
  }
  return 0; // not to call dfsan_set_label()
}

extern "C" dfsan_label
__dfsw___polytracker_taint_alloca(void *addr, uint64_t size, char* function
                                 /* rest of params are omitted */) {
  if (!polytracker_is_initialized()) {
    return 0;
  }
  return __polytracker_taint_alloca(addr, size, function);
}

extern "C" dfsan_label
__polytracker_taint_ctor(void *addr, uint64_t size, char *path, uint64_t line, uint64_t column, char* function) {
  if (addr == nullptr) {
    return 0;
  }

  // NOTE: allocaでテイントソースを再生成しない限り、テイントを引き継ぐのはオーバーテイント。
  //       なぜなら、別のスタックフレームでallocaされて参照されていたポインタ（addrs）が渡されることがあるから。
  {
    dfsan_label dest_label = dfsan_read_label(addr, sizeof(uint8_t));
    if (dest_label > 0) {
      __polytracker_log_label(dest_label, (char *) "ctor", path, line, column, function);
      return dest_label;
    } 
  }

  // ctor(0x0000000000000000,size=0000)
  char name[35] = {};
  snprintf(name, sizeof(name), "ctor(%p,size=%ld)", addr, size);

  auto rng = get_polytracker_tdag().create_taint_source(
    name, {reinterpret_cast<uint8_t *>(addr), size});
  if (rng) {
    dprintf(POLYLOG_FD, "[*] Create taint source by ctor: address=%p, size=%ld, label=%d:%d\n", addr, size, rng->first, rng->second); // DEBUG: 
    __polytracker_log_label(rng->first, (char *) "ctor", path, line, column, function);
    if (log_untainted_labels_mode) {
      dprintf(POLYLOG_FD, "[*] __polytracker_taint_ctor: dfsan_read_label(addr=%p, sizeof(uint8_t))=%d\n", addr, dfsan_read_label(addr, sizeof(uint8_t))); // DEBUG: 
    }
    return rng->first;
  } else {
    dprintf(POLYLOG_FD, "[!] Failed to create taint source for ctor: address=%p, size=%ld\n", addr, size); // DEBUG: 
  }
  return 0; // not to call dfsan_set_label()
}

extern "C" dfsan_label
__dfsw___polytracker_taint_ctor(void *addr, uint64_t size, char *path, uint64_t line, uint64_t column, char* function
                                 /* rest of params are omitted */) {
  if (!polytracker_is_initialized()) {
    return 0;
  }
  return __polytracker_taint_ctor(addr, size, path, line, column, function);
}

extern "C" void
__polytracker_set_taint_label(uint8_t *addr, uint64_t size, dfsan_label start_label) {
  if (!polytracker_is_initialized()) {
    return;
  }

  if (addr && start_label > 0) {
    for (uint64_t i = 0; i < size; i++) {
      dfsan_set_label(start_label + i, reinterpret_cast<void*>(&addr[i]), sizeof(uint8_t));
    }
    if (log_untainted_labels_mode) {
      dprintf(POLYLOG_FD, "[*] __polytracker_set_taint_label: start_label=%d, addr=%p, size=%ld\n", start_label, addr, size); // DEBUG:
    }
  }
}

extern "C" void
__polytracker_memcpy(uint8_t *dest, const uint8_t *src, size_t n, char *path, uint64_t line, uint64_t column, char* function) {
  if (!polytracker_is_initialized()) {
    return;
  }

  if (log_untainted_labels_mode) {
    dprintf(POLYLOG_FD, "[*] __polytracker_memcpy: dest=%p, src=%p, n=%#lx\n", dest, src, n); // DEBUG:
  }
  for (size_t i = 0; i < n; i++) {
    dfsan_label src_label = dfsan_read_label(src + i, sizeof(uint8_t));
    if (src_label > 0) {
      dfsan_label dest_label = dfsan_read_label(dest + i, sizeof(uint8_t));
      dfsan_set_label(src_label, dest + i, sizeof(uint8_t));
      if (dest_label > 0) {
        fprintf(
          polytracker_label_log_file, 
          "- { kind: update, cause: memcpy, old_label: %d, new_label: %d, path: %s, line: %lu, column: %lu, function: %s }\n", 
          dest_label, src_label, path, line, column, function
        );
        fflush(polytracker_label_log_file);
      }
    }
  }
}

extern "C" void
__polytracker_log_dominator(uint64_t dominator, uint64_t dominates, dfsan_label dominator_label, dfsan_label dominates_label) {
  if (!polytracker_is_initialized()) {
    return;
  }
  if (dominator_label != 0 && dominates_label != 0) {
    fprintf(polytracker_label_log_file,
            "- { kind: dominator, dominator: %d, dominates: %d }\n", 
            dominator_label, dominates_label
    );
    fflush(polytracker_label_log_file);
  }
}

extern "C" void
__dfsw___polytracker_log_dominator(uint64_t dominator, uint64_t dominates,
                                            dfsan_label dominator_label, dfsan_label dominates_label) {
  if (!polytracker_is_initialized()) {
    return;
  }
  __polytracker_log_dominator(dominator, dominates, dominator_label, dominates_label);
}

extern "C" void __taint_start() {
  taint_start();
  polytracker_initialize();

  char *log_file_name = getenv("POLYPATH_LOG_FILE");
  if (log_file_name) {
    printf("POLYPATH_LOG_FILE: %s\n", log_file_name);
    polytracker_label_log_file = fopen(log_file_name, "w");
  } else {
    polytracker_label_log_file = fopen("label.log", "w");
  }

  char *log_poly = getenv("POLYLOG");
  int fd;
  if (log_poly) {
    printf("POLYLOG: %s\n", log_poly);
    fd = open(log_poly, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  } else {
    fd = open("polytracker.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
  }
  dup2(fd, POLYLOG_FD);

  if (polytracker_label_log_file == NULL) {
    perror("Cannot open label log file");
  }

  if (getenv("POLY_LOG_UNTAINTED_LABELS")) {
    printf("POLY_LOG_UNTAINTED_LABELS: true\n");
    log_untainted_labels_mode = true;
  }
}

bool finished_taint_start = false;
extern "C" void __polytracker_taint_argv(int argc, char *argv[]) {
  polytracker::taint_argv(argc, argv);
  finished_taint_start = true;
}

extern "C" uint64_t __dfsw___polytracker_log_tainted_control_flow(
    uint64_t conditional, uint32_t functionid, dfsan_label conditional_label,
    dfsan_label function_label, dfsan_label *ret_label) {
  if (!polytracker_is_initialized()) {
    return 0;
  }
  if (conditional_label > 0) {
    get_polytracker_tdag().log_tainted_control_flow(conditional_label,
                                                    functionid);
  }
  *ret_label = conditional_label;
  return conditional;
}

extern "C" void __polytracker_enter_function(uint32_t function_id) {
  if (!polytracker_is_initialized()) {
    return;
  }
  get_polytracker_tdag().enter_function(function_id);
}

extern "C" void __polytracker_leave_function(uint32_t function_id) {
  if (!polytracker_is_initialized()) {
    return;
  }
  get_polytracker_tdag().leave_function(function_id);
}