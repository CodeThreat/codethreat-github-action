const core = require("@actions/core");
const github = require("@actions/github");
const axios = require("axios");
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
  getOrg
} = require("./utils");

let token = process.env.ACCESS_TOKEN;
let ctServer = process.env.CT_SERVER;
const githubtoken = process.env.GITHUB_TOKEN;
const username = process.env.USERNAME;
const password = process.env.PASSWORD;
const orgname = process.env.ORGNAME;

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

const octokit = new Octokit({
  auth: githubtoken,
});

let scanProcess, authToken, checked;
ctServer = ctServer.trim().replace(/\/+$/, '')

console.log("------------------------------")
console.log("CodeThreat Server: " + ctServer);
console.log("User: " + repoOwner);
console.log("Project: " + repoName);
console.log("Organization: " + orgname)
console.log("------------------------------")

const loginIn = async () => {
  if (token && (!username || !password)) {
    authToken = token;
    await getOrg(ctServer, authToken, orgname)
  } else if (username && password) {
    authToken = await login(ctServer, username, password);
  } else {
    core.setFailed("Please enter username and password or token.");
  }
};

const checkProject = async () => {
  return await check(ctServer, repoName, authToken, orgname);
};

const createProject = async () => {
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
  return await start(
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
};

const scanStatus = async (sid) => {
  try {
    scanProcess = await status(ctServer, sid, authToken, orgname);
    if (scanProcess.state === "failure") {
      core.setFailed("Scan Failed.");
      throw new Error("Scan Failed.");
    }
    if(!output.sync_scan){
      console.log("[CodeThreat]: Scan started successfuly.")
      return;
    }
    if (scanProcess.state !== "end") {

      core.warning(`[CodeThreat]: Scan Status | Scanning... `);

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
          core.setFailed("!! FAILED_ARGS : Critical limit exceeded.");
          throw new Error(
            "Pipeline interrupted because the FAILED_ARGS arguments you entered were found..."
          );
        } else if (
          output.max_number_of_critical &&
          output.max_number_of_high < scanProcess.severities.high
        ) {
          core.setFailed("!! FAILED_ARGS : High limit exceeded. ");
          throw new Error(
            "Pipeline interrupted because the FAILED_ARGS arguments you entered were found..."
          );
        } else if (weaknessIsCount.length > 0) {
          core.setFailed(
            "!! FAILED_ARGS : Weaknesses entered in the weakness_is key were found during the scan."
          );
          throw new Error(
            "Pipeline interrupted because the FAILED_ARGS arguments you entered were found..."
          );
        }
      } else if (output.condition === "AND") {
        if (
          (output.max_number_of_critical &&
            output.max_number_of_critical < scanProcess.severities.critical) ||
          (output.max_number_of_critical &&
            output.max_number_of_high < scanProcess.severities.high) ||
          weaknessIsCount.length > 0
        ) {
          core.setFailed(
            "!! FAILED ARGS : Not all conditions are met according to the given arguments."
          );
          throw new Error(
            "Pipeline interrupted because the FAILED_ARGS arguments you entered were found..."
          );
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
  }
};

const resultScan = async (progress, severities, sid, weaknessesArr) => {
  const report = await result(ctServer, sid, authToken, orgname, branch, repoName);
  if(report.type === null) {
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
      console.log("!! FAILED_ARGS : Critical limit exceeded.");
      throw new Error(
        "Pipeline interrupted because the FAILED_ARGS arguments you entered were found..."
      );
    } else if (
      output.max_number_of_high &&
      output.max_number_of_high < scanProcess.severities.high
    ) {
      console.log("!! FAILED_ARGS : High limit exceeded. ");
      throw new Error(
        "Pipeline interrupted because the FAILED_ARGS arguments you entered were found..."
      );
    } else if (weaknessIsCount.length > 0) {
      console.log(
        "!! FAILED_ARGS : Weaknesses entered in the weakness_is key were found during the scan."
      );
      throw new Error(
        "Pipeline interrupted because the FAILED_ARGS arguments you entered were found..."
      );
    } else if (
      output.sca_max_number_of_critical &&
      output.sca_max_number_of_critical < report.scaSeverityCounts.Critical
    ) {
      console.log("!! FAILED_ARGS : Sca Critical limit exceeded.");
      throw new Error(
        "Pipeline interrupted because the FAILED_ARGS arguments you entered were found..."
      );
    } else if (
      output.sca_max_number_of_high &&
      output.sca_max_number_of_high < report.scaSeverityCounts.High
    ) {
      console.log("!! FAILED_ARGS : Sca High limit exceeded. ");
      throw new Error(
        "Pipeline interrupted because the FAILED_ARGS arguments you entered were found..."
      );
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
      console.log(
        "!! FAILED ARGS : Not all conditions are met according to the given arguments."
      );
      throw new Error(
        "Pipeline interrupted because the FAILED_ARGS arguments you entered were found..."
      );
    }
  }

  core.warning("[CodeThreat]: Scan completed successfully.")

  if (github.context.eventName === "push") {
    try {
      await octokit.repos.createCommitComment({
        owner: repoOwner,
        repo: repoName,
        commit_sha: commitId,
        body: report.report,
      });
      core.warning("[CodeThreat]: Report Created.")
    } catch (error) {
      core.setFailed(error.message);
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
        core.warning("[CodeThreat]: Report Created.")
      } catch (error) {
        core.setFailed(error.message);
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
        core.warning("[CodeThreat]: Report Created.")
      } catch (error) {
        core.setFailed(error.message);
      }
    }
  }
  saveSarif(ctServer, sid, authToken, orgname, repoName, branch)
  .then(() => console.log('[CodeThreat]: SARIF report generation and saving completed.'))
  .catch(error => console.error(error));
};

(async () => {
  let start;
  try {
    await loginIn();
    checked = await checkProject();
    if (checked.type === null) await createProject();
    start = await startScan();
    if (start && start.data && start.data.scan_id) {
      await scanStatus(start.data.scan_id);
    }
  } catch (error) {
    throw new Error(error);
  }
})();
