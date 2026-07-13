#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <link.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

/* ========== 配置常量区 ========== */

static const uintptr_t kWA_Base                 = 0x8048000u;

static const uintptr_t kWA_GetEquipmentType_va  = 0x8990f1fu; // 获取装备类型
static const uintptr_t kWA_IsAvatarItem_va      = 0x8514d46u; // 判断是否是时装物品
static const uintptr_t kWA_IsEquipable_va       = 0x85003beu;  // 判断物品是否可装备

// CEquipItem 类中装备类型字段的偏移
#define WA_CEQUIPITEM_TYPE_OFFSET 0x234
// 武器装扮对应的枚举值
#define WA_WEAPON_AVATAR_ENUM 100
// 备用枚举值
#define WA_FALLBACK_ENUM       26
// 普通时装枚举值范围
#define WA_AVATAR_ENUM_MIN     0
#define WA_AVATAR_ENUM_MAX     9

/* ========== 函数指针类型定义 ========== */
typedef int  (*FnGetEquipmentType)(const char *s);
typedef int  (*FnIsAvatarItem)(const void *this_ptr);
typedef int  (*FnIsEquipable)(void *user, const void *item, int slot);

/* ========== 全局变量区 ========== */
static uintptr_t gWA_MainBase;       // 游戏主程序基址
static FILE     *gWA_Fp;              // 日志文件指针
static const char *kWA_LogDefault = "/home/neople/game/log/df_game_r_weapon_avatar_fix.log"; // 默认日志路径
static int gWA_Enabled  = 1;          // 修复功能是否启用
static int gWA_Installed;             // Hook 是否安装成功

// 统计用的计数器（原子操作）
static volatile unsigned gWA_GET_hitEnter;
static volatile unsigned gWA_GET_hitMatch;
static volatile unsigned gWA_IAI_hitEnter;
static volatile unsigned gWA_IAI_hitWA;
static volatile unsigned gWA_IE_hitEnter;
static volatile unsigned gWA_IE_hitForce;

// 跳板代码缓冲区（用于保存被覆盖的原函数开头指令）
static uint8_t gWA_Tramp_GET[24] __attribute__((aligned(16)));
static uint8_t gWA_Tramp_IAI[24] __attribute__((aligned(16)));
static uint8_t gWA_Tramp_IE [24] __attribute__((aligned(16)));

// 原函数的跳板函数指针
static FnGetEquipmentType gWA_Trampoline_GET;
static FnIsAvatarItem     gWA_Trampoline_IAI;
static FnIsEquipable      gWA_Trampoline_IE;

/* ========== 工具函数：日志输出（已全部注释） ========== */
static void wa_log(const char *fmt, ...) {
    // if (!fmt) return;
    
    // // 获取当前时间
    // time_t t = time(NULL);
    // struct tm m;
    // localtime_r(&t, &m);
    
    // // 输出到 stderr
    // va_list a;
    // va_start(a, fmt);
    // fprintf(stderr, "[WA %02d:%02d:%02d] ", m.tm_hour, m.tm_min, m.tm_sec);
    // vfprintf(stderr, fmt, a);
    // fflush(stderr);
    // va_end(a);
    
    // // 输出到日志文件
    // if (gWA_Fp) {
    //     va_start(a, fmt);
    //     fprintf(gWA_Fp, "[WA %02d:%02d:%02d] ", m.tm_hour, m.tm_min, m.tm_sec);
    //     vfprintf(gWA_Fp, fmt, a);
    //     fflush(gWA_Fp);
    //     va_end(a);
    // }
}

/* ========== 工具函数：获取游戏主程序基址 ========== */
static int wa_dl_cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    if (!info) return 0;
    // 找到名称为空的段，即主程序
    if (!info->dlpi_name || info->dlpi_name[0] == '\0') {
        *(uintptr_t *)data = (uintptr_t)info->dlpi_addr;
        return 1;
    }
    return 0;
}

static uintptr_t wa_mainbase(void) {
    if (gWA_MainBase) return gWA_MainBase;
    uintptr_t b = 0;
    dl_iterate_phdr(wa_dl_cb, &b);
    gWA_MainBase = b;
    return b;
}

// 将地址转换为运行时实际地址
static uintptr_t wa_va(uintptr_t ida_va) {
    uintptr_t b = wa_mainbase();
    return (b && ida_va >= kWA_Base) ? b + (ida_va - kWA_Base) : ida_va;
}

/* ========== 工具函数：内存修改（加写权限+写回+清缓存） ========== */
static int wa_pmem(void *dst, const void *src, size_t n) {
    long ps = sysconf(_SC_PAGESIZE);
    if (!dst || !src || !n || ps <= 0) return -1;
    
    // 计算页边界并加读写执行权限
    uintptr_t a = ((uintptr_t)dst) & ~(uintptr_t)(ps - 1);
    uintptr_t e = (((uintptr_t)dst + n + ps - 1) & ~(uintptr_t)(ps - 1));
    if (mprotect((void *)a, e - a, PROT_READ | PROT_WRITE | PROT_EXEC)) return -2;
    
    // 复制数据并清除 CPU 指令缓存
    memcpy(dst, src, n);
    __builtin___clear_cache((char *)dst, (char *)dst + n);
    return 0;
}

// 仅给内存加执行权限
static int wa_mark_exec(void *addr, size_t n) {
    long ps = sysconf(_SC_PAGESIZE);
    if (!addr || !n || ps <= 0) return -1;
    uintptr_t a = ((uintptr_t)addr) & ~(uintptr_t)(ps - 1);
    uintptr_t e = (((uintptr_t)addr + n + ps - 1) & ~(uintptr_t)(ps - 1));
    if (mprotect((void *)a, e - a, PROT_READ | PROT_WRITE | PROT_EXEC)) return -2;
    return 0;
}

// 构造 6 字节绝对跳转指令：push addr; ret
static int wa_patch_abs_jmp6(void *at, const void *to) {
    uint8_t b[6];
    b[0] = 0x68;                                  // push 立即数
    *(uint32_t *)(b + 1) = (uint32_t)(uintptr_t)to; // 目标地址
    b[5] = 0xC3;                                  // ret
    return wa_pmem(at, b, 6);
}

/* ========== 核心 Hook 函数 1：GetEquipmentType ========== */
// 功能：当遇到 "[weapon avatar]" 字符串时，强制返回武器装扮枚举值 100
static int wa_hook_GetEquipmentType(const char *s) {
    __sync_add_and_fetch(&gWA_GET_hitEnter, 1);
    
    // 检查是否是武器装扮的字符串
    if (s && strcmp(s, "[weapon avatar]") == 0) {
        unsigned n = __sync_add_and_fetch(&gWA_GET_hitMatch, 1);
        // 每 1024 次或第一次打印日志（已注释）
        // if (n == 1 || (n & 0x3FF) == 0) {
        //     wa_log("GetEquipmentType('[weapon avatar]') -> %d  hit=%u\n",
        //            WA_WEAPON_AVATAR_ENUM, n);
        // }
        return WA_WEAPON_AVATAR_ENUM; // 强制返回武器装扮类型
    }
    
    // 不是武器装扮，调用原函数
    if (!gWA_Trampoline_GET) return WA_FALLBACK_ENUM;
    return gWA_Trampoline_GET(s);
}

/* ========== 核心 Hook 函数 2：IsAvatarItem ========== */
// 功能：判断物品是否是时装，将武器装扮(100)也纳入时装范围
static int wa_hook_IsAvatarItem(const void *this_ptr) {
    __sync_add_and_fetch(&gWA_IAI_hitEnter, 1);
    if (!this_ptr) return 0;
    
    // 读取物品的类型字段
    int type = *(const int *)((const char *)this_ptr + WA_CEQUIPITEM_TYPE_OFFSET);
    
    // 判断：普通时装(0-9) 或 武器装扮(100) 都算时装
    int is_avatar = (type >= WA_AVATAR_ENUM_MIN && type <= WA_AVATAR_ENUM_MAX) ||
                    (type == WA_WEAPON_AVATAR_ENUM);
    
    // 如果是武器装扮，打印日志（已注释）
    if (type == WA_WEAPON_AVATAR_ENUM) {
        unsigned n = __sync_add_and_fetch(&gWA_IAI_hitWA, 1);
        // if (n == 1 || (n & 0x3FF) == 0) {
        //     wa_log("IsAvatarItem: type=%d (weapon avatar) -> true  hit=%u\n",
        //            type, n);
        // }
    }
    
    return is_avatar ? 1 : 0;
}

/* ========== 核心 Hook 函数 3：IsEquipable ========== */
// 功能：让武器装扮可以装备到对应的槽位
static int wa_hook_IsEquipable(void *user, const void *item, int slot) {
    __sync_add_and_fetch(&gWA_IE_hitEnter, 1);
    
    if (!item || !gWA_Trampoline_IE) {
        return gWA_Trampoline_IE ? gWA_Trampoline_IE(user, item, slot) : 17;
    }
    
    // 检查虚表，确认是 CEquipItem 对象
    void **vtbl = *(void ***)item;
    if (vtbl && vtbl[3] == (void *)0x8514d26u) {
        // 读取物品类型
        int type = *(const int *)((const char *)item + WA_CEQUIPITEM_TYPE_OFFSET);
        
        // 如果是武器装扮，强制将 slot 改为 type，让它装备到正确的位置
        if (type == WA_WEAPON_AVATAR_ENUM) {
            unsigned n = __sync_add_and_fetch(&gWA_IE_hitForce, 1);
            // wa_log("IsEquipable WEAPON_AVATAR: type=%d slot=%d -> faking slot=%d  hit=%u\n",
            //        type, slot, type, n);
            // 调用原函数，但 slot 参数换成 type
            return gWA_Trampoline_IE(user, item, type);
        }
    }
    
    // 不是武器装扮，正常调用原函数
    return gWA_Trampoline_IE(user, item, slot);
}

/* ========== 通用 Hook 安装函数 ========== */
static int wa_install_detour(const char *name,
                             uintptr_t ida_va,
                             const uint8_t *expected_prologue,
                             size_t prologue_size,
                             uint8_t *tramp_buf, size_t tramp_size,
                             void *hook_fn,
                             void **tramp_out) {
    // 1. 转换地址
    uintptr_t tgt = wa_va(ida_va);
    if (!tgt) {
        // wa_log("%s install FAIL: cannot resolve target VA\n", name);
        return -1;
    }
    
    // 2. 检查参数合法性
    if (prologue_size < 6 || prologue_size > 16) {
        // wa_log("%s install FAIL: bad prologue_size=%zu\n", name, prologue_size);
        return -6;
    }
    if (tramp_size < prologue_size + 6) {
        // wa_log("%s install FAIL: tramp_size=%zu < prologue_size+6=%zu\n",
        //        name, tramp_size, prologue_size + 6);
        return -7;
    }
    
    // 3. 校验原函数开头字节是否匹配（防止版本不对）
    const uint8_t *code = (const uint8_t *)tgt;
    // wa_log("%s target prologue (%zuB): %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
    //        name, prologue_size,
    //        code[0], code[1], code[2], code[3], code[4], code[5],
    //        prologue_size > 6 ? code[6] : 0,
    //        prologue_size > 7 ? code[7] : 0,
    //        prologue_size > 8 ? code[8] : 0);
    
    for (size_t i = 0; i < prologue_size; i++) {
        if (code[i] != expected_prologue[i]) {
            // wa_log("%s install FAIL: prologue mismatch at byte %zu (got %02x, expect %02x)\n",
            //        name, i, code[i], expected_prologue[i]);
            return -2;
        }
    }
    
    // 4. 准备跳板：先给跳板缓冲区加执行权限
    if (wa_mark_exec(tramp_buf, tramp_size) != 0) {
        // wa_log("%s install FAIL: trampoline mprotect errno=%d (%s)\n",
        //        name, errno, strerror(errno));
        return -3;
    }
    
    // 5. 复制原函数开头的指令到跳板
    memcpy(tramp_buf, code, prologue_size);
    
    // 6. 在跳板末尾加一个跳回原函数的指令
    if (wa_patch_abs_jmp6(tramp_buf + prologue_size, (const void *)(tgt + prologue_size)) != 0) {
        // wa_log("%s install FAIL: trampoline tail abs_jmp6\n", name);
        return -4;
    }
    
    *tramp_out = (void *)tramp_buf;
    
    // 7. 最后：修改原函数开头，让它跳转到我们的 hook 函数
    if (wa_patch_abs_jmp6((void *)tgt, hook_fn) != 0) {
        // wa_log("%s install FAIL: target abs_jmp6 errno=%d (%s)\n",
        //        name, errno, strerror(errno));
        *tramp_out = NULL;
        return -5;
    }
    
    // wa_log("%s detour OK: target=0x%08x hook=%p tramp=%p (prologue=%zuB)\n",
    //        name, (unsigned)tgt, hook_fn, (void *)tramp_buf, prologue_size);
    return 0;
}

/* ========== 初始化入口（库加载时自动执行） ========== */
__attribute__((constructor))
static void wa_init(void) {
    // 检查环境变量是否禁用此修复
    const char *disabled = getenv("DNF_WEAPON_AVATAR_FIX");
    if (disabled && !strcmp(disabled, "0")) {
        gWA_Enabled = 0;
    }
    if (!gWA_Enabled) {
        // fprintf(stderr, "[WA] disabled via DNF_WEAPON_AVATAR_FIX=0\n");
        return;
    }
    
    // 打开日志文件（保留代码，实际不会写入）
    const char *logp = getenv("DNF_WEAPON_AVATAR_LOG");
    if (!logp || !logp[0]) logp = kWA_LogDefault;
    gWA_Fp = fopen(logp, "a");
    
    // wa_log("df_game_r_weapon_avatar_fix v2 loading...\n");
    (void)wa_mainbase();
    // wa_log("main image base = 0x%08x\n", (unsigned)gWA_MainBase);
    
    // 定义三个函数预期的开头字节（用于校验版本）
    static const uint8_t prologue_GET[6] = { 0x55, 0x89, 0xE5, 0x83, 0xEC, 0x28 };
    static const uint8_t prologue_IAI[6] = { 0x55, 0x89, 0xE5, 0x8B, 0x45, 0x08 };
    static const uint8_t prologue_IE [9] = { 0x55, 0x89, 0xE5, 0x57, 0x56, 0x53, 0x83, 0xEC, 0x4C };
    
    // 安装三个 Hook
    int rc1 = wa_install_detour("GetEquipmentType",
                                kWA_GetEquipmentType_va,
                                prologue_GET, sizeof(prologue_GET),
                                gWA_Tramp_GET, sizeof(gWA_Tramp_GET),
                                (void *)&wa_hook_GetEquipmentType,
                                (void **)&gWA_Trampoline_GET);
    
    int rc2 = wa_install_detour("CEquipItem::IsAvatarItem",
                                kWA_IsAvatarItem_va,
                                prologue_IAI, sizeof(prologue_IAI),
                                gWA_Tramp_IAI, sizeof(gWA_Tramp_IAI),
                                (void *)&wa_hook_IsAvatarItem,
                                (void **)&gWA_Trampoline_IAI);
    
    int rc3 = wa_install_detour("IsEquipable",
                                kWA_IsEquipable_va,
                                prologue_IE, sizeof(prologue_IE),
                                gWA_Tramp_IE, sizeof(gWA_Tramp_IE),
                                (void *)&wa_hook_IsEquipable,
                                (void **)&gWA_Trampoline_IE);
    
    // 检查是否全部安装成功
    int all_ok = (rc1 == 0 && rc2 == 0 && rc3 == 0);
    if (all_ok) {
        gWA_Installed = 1;
        // wa_log("ALL hooks installed.\n");
        // wa_log("  - GetEquipmentType: '[weapon avatar]' -> enum %d\n", WA_WEAPON_AVATAR_ENUM);
        // wa_log("  - IsAvatarItem: accepts 0..%d and %d\n", WA_AVATAR_ENUM_MAX, WA_WEAPON_AVATAR_ENUM);
        // wa_log("  - IsEquipable: type=%d items equip at any slot\n", WA_WEAPON_AVATAR_ENUM);
    } else {
        // wa_log("PARTIAL FAIL (rc_GET=%d rc_IAI=%d rc_IE=%d)\n", rc1, rc2, rc3);
    }
}
