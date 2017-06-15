import rollupNodeResolve from "rollup-plugin-node-resolve";

export default [
	{
	entry: "es6.js",
	dest: "../csr_generator.js",
	format: "iife",
	outro: `window.createPKCS10 = createPKCS10;
		function context(name, func) {}`,
	plugins: [
		rollupNodeResolve({ jsnext: true, main: true })
	]
	},

	{
	entry: "es6.js",
	dest: "../csr_generator.js",
	intro: `const WebCrypto = require("node-webcrypto-ossl");
		const webcrypto = new WebCrypto();`,
	outro: `const assert = require("assert");
		setEngine("newEngine", webcrypto, webcrypto.subtle);`,
	plugins: [
		rollupNodeResolve({ jsnext: true, main: true })
	]
	},

	{
	entry: "es6.js",
	dest: "../csr_generator.js",
	plugins: [
		rollupNodeResolve({ jsnext: true, main: true })
	]
	}
];
