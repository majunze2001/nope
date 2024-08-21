const path = require("path");
const TerserPlugin = require("terser-webpack-plugin");

module.exports = {
    entry: {
        background_scripts: "./background_scripts/background.js",
    },
    output: {
        path: path.resolve(__dirname, "addon"),
        filename: "background_scripts/index.js"
    },
    mode: 'none',
    optimization: {
        minimize: true, // Enable minification
        minimizer: [new TerserPlugin({
            terserOptions: {
                // Terser options can be adjusted here
                keep_classnames: false,
                keep_fnames: false
            }
        })],
    },
};
