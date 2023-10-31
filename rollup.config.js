import commonjs from "@rollup/plugin-commonjs"
import typescript from "@rollup/plugin-typescript"

const production = !process.env.ROLLUP_WATCH

const outdir = (fmt, env) => {
  if (env === "node") {
    return `dist/node`
  } else {
    return `dist/${fmt}${env === "slim" ? "-slim" : ""}`
  }
}

const rolls = (fmt, env) => ({
  input: env !== "slim" ? "index.ts" : "src / index_slim.ts",
  output: {
    dir: outdir(fmt, env),
    format: fmt,
    entryFileNames: `[name].${fmt === "cjs" ? "cjs" : "js"}`,
    name: "cloudproof_kms_js",
  },
  external: ["jose"],
  plugins: [
    commonjs(),
    typescript({
      outDir: outdir(fmt, env),
      rootDir: "src",
      sourceMap: !production,
    }),
  ],
})

export default [
  rolls("umd", "fat"),
  rolls("es", "fat"),
  rolls("cjs", "fat"),
  rolls("cjs", "node"),
  //   rolls("es", "slim"),
  //   rolls("cjs", "slim"),
]
