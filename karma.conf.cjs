// Karma harness for cljs.test under headless Chromium.
// Test entrypoint is produced by `shadow-cljs compile client-test`.
module.exports = function (config) {
  config.set({
    browsers: ['ChromeHeadlessNoSandbox'],
    customLaunchers: {
      ChromeHeadlessNoSandbox: {
        base: 'ChromeHeadless',
        flags: ['--no-sandbox', '--disable-dev-shm-usage'],
      },
    },
    basePath: '',
    files: ['target/karma-test.js'],
    frameworks: ['cljs-test'],
    plugins: [
      'karma-cljs-test',
      'karma-chrome-launcher',
      'karma-junit-reporter',
    ],
    colors: true,
    logLevel: config.LOG_INFO,
    client: {
      args: ['shadow.test.karma.init'],
    },
    singleRun: false,
    reporters: ['progress', 'junit'],
    junitReporter: {
      outputDir: '.test-reports',
      outputFile: 'karma.xml',
      useBrowserName: false,
    },
  });
};
