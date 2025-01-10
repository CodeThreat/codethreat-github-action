const core = require("@actions/core");
const github = require("@actions/github");
const { Octokit } = require("@octokit/rest");
const yaml = require("js-yaml");

const {
  findWeaknessTitles,
  failedArgs,
  login,
  check,
  create,
  start,
  status,
  result,
  saveSarif,
  getOrg,
  getEnvVars
} = require("./utils");

const getOctokit = () => {
  const { githubtoken } = getEnvVars();
  return new Octokit({
    auth: githubtoken,
  });
};

const repoName = github.context.repo.repo;
const repoOwner = github.context.repo.owner;
const type = github.context.payload.repository.private ? "private" : "public";
let branch = github.context.ref.includes("refs/heads/")
          ? github.context.ref.split("refs/heads/")[1]
          : github.context.ref
let repoId = github.context.payload.repository.id;

let pr;
if (github.context.eventName === "pull_request") {
  pr = github.context.payload.pull_request;
  branch = pr.base.ref
  repoId = pr.head.repo.owner.id;
}

const commitId = github.context.payload.after || pr?.head?.sha;
const committer = github.context.actor;
const commitMessage =
  github.context.payload?.head_commit?.message ||
  github.context.payload?.pull_request?.title;

const failedArgsInput = core.getInput("FAILED_ARGS") || {};
const failedArgsParsed = yaml.load(failedArgsInput);
const output = failedArgs(failedArgsParsed);

if (output.automerge === undefined) output.automerge = false;
if (output.condition === undefined) output.condition = "AND";
if (output.sync_scan === undefined) output.sync_scan = true;
if (output.weakness_is === undefined) output.weakness_is = "";
if (output.policy_name === undefined) output.policy_name = 'Advanced Security';

let scanProcess, authToken;

console.log("------------------------------")
console.log("CodeThreat Server: " + getEnvVars().ctServer);
console.log("User: " + repoOwner);
console.log("Project: " + repoName);
console.log("Organization: " + getEnvVars().orgname)
console.log("------------------------------")

const loginIn = async () => {
  try {
    const { token, ctServer, username, password, orgname } = getEnvVars();
    if (token && (!username || !password)) {
      authToken = token;
      await getOrg(ctServer, authToken, orgname);
    } else if (username && password) {
      authToken = await login(ctServer, username, password);
    } else {
      const error = new Error("Please enter username and password or token.");
      core.setFailed(error.message);
      throw error;
    }
  } catch (error) {
    core.setFailed(error.message);
    throw error;
  }
};

const checkProject = async () => {
  const { ctServer, orgname } = getEnvVars();
  return await check(ctServer, repoName, authToken, orgname);
};

const createProject = async () => {
  const { ctServer, githubtoken, orgname } = getEnvVars();
  return await create(
    ctServer,
    repoName,
    branch,
    repoOwner,
    type,
    githubtoken,
    repoId,
    authToken,
    orgname,
    output.policy_name
  );
};

const startScan = async () => {
  const { ctServer, githubtoken, orgname } = getEnvVars();
  const scanResult = await start(
    ctServer,
    repoName,
    branch,
    repoOwner,
    type,
    githubtoken,
    repoId,
    commitId,
    committer,
    commitMessage,
    authToken,
    orgname,
    output.policy_name,
  );

  if (scanResult && scanResult.data && scanResult.data.scan_id) {
    await scanStatus(scanResult.data.scan_id);
  }
  return scanResult;
};

const scanStatus = async (sid) => {
  try {
    const { ctServer, orgname } = getEnvVars();
    scanProcess = await status(ctServer, sid, authToken, orgname);
    if (scanProcess.state === "failure") {
      const error = new Error("Scan Failed.");
      core.setFailed(error.message);
      throw error;
    }
    if(!output.sync_scan){
      console.log("[CodeThreat]: Scan started successfuly.")
      return;
    }
    if (scanProcess.state !== "end") {
      core.warning("[CodeThreat]: Scan Status | Scanning... ");

      const weaknessArray = [...new Set(scanProcess.weaknessesArr)];
      let weaknessIsCount;
      if(output.weakness_is && output.weakness_is !== undefined && output.weakness_is !== ""){
        const keywords = output.weakness_is.split(",");
        weaknessIsCount = findWeaknessTitles(weaknessArray, keywords);
      } else {
        weaknessIsCount = [];
      }

      if (output.condition === "OR") {
        if (
          output.max_number_of_critical &&
          output.max_number_of_critical < scanProcess.severities.critical
        ) {
          const error = new Error("!! FAILED_ARGS : Critical limit exceeded.");
          core.setFailed(error.message);
          throw error;
        } else if (
          output.max_number_of_critical &&
          output.max_number_of_high < scanProcess.severities.high
        ) {
          const error = new Error("!! FAILED_ARGS : High limit exceeded.");
          core.setFailed(error.message);
          throw error;
        } else if (weaknessIsCount.length > 0) {
          const error = new Error(
            "!! FAILED_ARGS : Weaknesses entered in the weakness_is key were found during the scan."
          );
          core.setFailed(error.message);
          throw error;
        }
      } else if (output.condition === "AND") {
        if (
          (output.max_number_of_critical &&
            output.max_number_of_critical < scanProcess.severities.critical) ||
          (output.max_number_of_critical &&
            output.max_number_of_high < scanProcess.severities.high) ||
          weaknessIsCount.length > 0
        ) {
          const error = new Error(
            "!! FAILED ARGS : Not all conditions are met according to the given arguments."
          );
          core.setFailed(error.message);
          throw error;
        }
      }
    }
    if (scanProcess.state === "end") {
      await resultScan(
        scanProcess.progress,
        scanProcess.severities,
        sid,
        scanProcess.weaknessesArr
      );
    } else {
      setTimeout(function () {
        scanStatus(sid);
      }, 30000);
    }
  } catch (error) {
    core.setFailed(error.message);
    throw error;
  }
};

const resultScan = async (progress, severities, sid, weaknessesArr) => {
  try {
    const { ctServer, orgname } = getEnvVars();
    const report = await result(ctServer, sid, authToken, orgname, branch, repoName);
    if(!report || report.type === null) {
      console.log("[CodeThreat]: Scan completed successfully, but report not created.");
      return;
    }
    const weaknessArray = [...new Set(weaknessesArr)];
    let weaknessIsCount;
    if(output.weakness_is && output.weakness_is !== undefined && output.weakness_is !== ""){
      const keywords = output.weakness_is.split(",");
      weaknessIsCount = findWeaknessTitles(weaknessArray, keywords);
    } else {
      weaknessIsCount = [];
    }
    if (output.condition === "OR") {
      if (
        output.max_number_of_critical &&
        output.max_number_of_critical < scanProcess.severities.critical
      ) {
        const error = new Error("!! FAILED_ARGS : Critical limit exceeded.");
        core.setFailed(error.message);
        throw error;
      } else if (
        output.max_number_of_high &&
        output.max_number_of_high < scanProcess.severities.high
      ) {
        const error = new Error("!! FAILED_ARGS : High limit exceeded.");
        core.setFailed(error.message);
        throw error;
      } else if (weaknessIsCount.length > 0) {
        const error = new Error(
          "!! FAILED_ARGS : Weaknesses entered in the weakness_is key were found during the scan."
        );
        core.setFailed(error.message);
        throw error;
      } else if (
        output.sca_max_number_of_critical &&
        output.sca_max_number_of_critical < report.scaSeverityCounts.Critical
      ) {
        const error = new Error("!! FAILED_ARGS : Sca Critical limit exceeded.");
        core.setFailed(error.message);
        throw error;
      } else if (
        output.sca_max_number_of_high &&
        output.sca_max_number_of_high < report.scaSeverityCounts.High
      ) {
        const error = new Error("!! FAILED_ARGS : Sca High limit exceeded.");
        core.setFailed(error.message);
        throw error;
      }
    } else if (output.condition === "AND") {
      if (
        (output.max_number_of_critical &&
          output.max_number_of_critical < scanProcess.severities.critical) ||
        (output.max_number_of_high &&
          output.max_number_of_high < scanProcess.severities.high) ||
        (output.sca_max_number_of_high &&
          output.sca_max_number_of_high < report.scaSeverityCounts.High) ||
        (output.sca_max_number_of_critical &&
          output.sca_max_number_of_critical < report.scaSeverityCounts.Critical) ||
        weaknessIsCount.length > 0
      ) {
        const error = new Error(
          "!! FAILED ARGS : Not all conditions are met according to the given arguments."
        );
        core.setFailed(error.message);
        throw error;
      }
    }

    core.info("[CodeThreat]: Scan completed successfully.");

    const octokit = getOctokit();

    if (github.context.eventName === "push") {
      try {
        await octokit.repos.createCommitComment({
          owner: repoOwner,
          repo: repoName,
          commit_sha: commitId,
          body: report.report,
        });
        core.info("[CodeThreat]: Report Created.");
      } catch (error) {
        core.setFailed(error.message);
        throw error;
      }
    }

    if (github.context.eventName === "pull_request") {
      if (output.automerge) {
        try {
          await octokit.pulls.update({
            owner: repoOwner,
            repo: repoName,
            pull_number: pr.number,
            state: "closed",
          });
          await octokit.pulls.merge({
            owner: repoOwner,
            repo: repoName,
            pull_number: pr.number,
          });
          core.info("[CodeThreat]: Report Created.");
        } catch (error) {
          core.setFailed(error.message);
          throw error;
        }
      } else {
        try {
          await octokit.pulls.createReview({
            owner: repoOwner,
            repo: repoName,
            pull_number: pr.number,
            event: "COMMENT",
            body: report.report,
          });
          core.info("[CodeThreat]: Report Created.");
        } catch (error) {
          core.setFailed(error.message);
          throw error;
        }
      }
    }
    await saveSarif(ctServer, sid, authToken, orgname, repoName, branch);
    core.info('[CodeThreat]: SARIF report generation and saving completed.');
  } catch (error) {
    core.setFailed(error.message);
    throw error;
  }
};

// Export functions for testing
module.exports = {
  loginIn,
  checkProject,
  createProject,
  startScan,
  scanStatus,
  resultScan
};

// Run if not being required (i.e., if being run directly)
if (require.main === module) {
  (async () => {
    try {
      await loginIn();
      const checked = await checkProject();
      if (checked.type === null) await createProject();
      const start = await startScan();
    } catch (error) {
      core.setFailed(error.message);
      throw error;
    }
  })();
}
