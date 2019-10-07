async function load() {
	let binary = await fetch('goteam.wasm');
	let bytes = await binary.arrayBuffer();
	let module = await WebAssembly.compile(bytes);
	let instance = await WebAssembly.Instance(module);
	console.log(instance);
	return instance;
}

load();