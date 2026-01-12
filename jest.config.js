module.exports = {
  projects: [
    {
      displayName: "service-worker",
      testEnvironment: "node",
      testMatch: ["<rootDir>/service_worker*.test.js"],
      collectCoverageFrom: ["service_worker.js"]
    },
    {
      displayName: "popup-ui",
      testEnvironment: "jsdom",
      testMatch: ["<rootDir>/popup.ui.test.js"],
      setupFilesAfterEnv: [],
      testPathIgnorePatterns: ["/node_modules/"]
    }
  ],
  collectCoverageFrom: [
    "*.js",
    "!*.test.js",
    "!jest.config.js",
    "!node_modules/**"
  ]
};
