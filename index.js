const core = require("@actions/core");
const github = require("@actions/github");
const axios = require("axios");
const { Octokit } = require("@octokit/rest");
const yaml = require("js-yaml");

const {
  countAndGroupByTitle,
  convertToHHMMSS,
  getScore,
  countBySeverity,
  htmlCode,
  findWeaknessTitles,
  newIssue,
  allIssue,
  failedArgs,
} = require("./utils");

let token = process.env.ACCESS_TOKEN;
const githubtoken = process.env.GITHUB_TOKEN;
const ctServer = process.env.CT_SERVER;
const username = process.env.USERNAME;
const password = process.env.PASSWORD;
const repoName = github.context.repo.repo;
const repoOwner = github.context.repo.owner;
const pr = github.context.payload.pull_request;
const type = github.context.payload.repository.private ? "private" : "public";
let branch = github.context.payload.pull_request?.head.ref;
let repoId = github.context.payload.pull_request?.head.repo.owner.id;

if (github.context.eventName === "push") {
  branch = github.context.payload.repository.default_branch;
  repoId = github.context.payload.repository.id;
}

const failedArgsInput = core.getInput("FAILED_ARGS");
const failedArgsParsed = yaml.load(failedArgsInput);
const output = failedArgs(failedArgsParsed);

if (output.automerge === undefined) output.automerge = false;
if (output.condition === undefined) output.condition = "AND";

const octokit = new Octokit({
  auth: githubtoken,
});

let scanProcess, cancellation;

const startScan = async () => {
  try {
    let responseToken;
    if (!token && username && password) {
      const b64uidpss = btoa(`${username}:${password}`);
      const authorization = `Basic ${b64uidpss}`;
      responseToken = await axios.post(`${ctServer}/api/signin`, {
        client_id: username,
        client_secret: password,
      });
    }
    responseToken?.data.access_token
      ? (token = responseToken.data.access_token)
      : token;
    const scanStarting = await axios.post(
      `${ctServer}/api/integration/github/start`,
      {
        project: repoName,
        branch: branch,
        account: repoOwner,
        type: type,
        githubtoken: githubtoken,
        id: repoId,
        action: true,
      },
      {
        headers: {
          Authorization: token,
          "x-ct-organization": "codethreat",
        },
      }
    );
    return scanStarting;
  } catch (error) {
    core.setFailed(error.message);
  }
};

let progressData = [];
let progressSeverity = [];

const awaitScan = async (sid) => {
  try {
    scanProcess = await axios.get(`${ctServer}/api/scan/status/${sid}`, {
      headers: {
        Authorization: token,
        "x-ct-organization": "codethreat",
      },
    });
    progressData.push(scanProcess.data.progress_data.progress);
    progressSeverity.push(scanProcess.data.severities);
    if (scanProcess.data.state !== "end") {
      console.log(`Scanning... ` + `%` + progressData[progressData.length - 1]);
      progressSeverity[progressSeverity.length - 1].critical
        ? progressSeverity[progressSeverity.length - 1].critical
        : (progressSeverity[progressSeverity.length - 1].critical = 0);
      progressSeverity[progressSeverity.length - 1].high
        ? progressSeverity[progressSeverity.length - 1].hgih
        : (progressSeverity[progressSeverity.length - 1].high = 0);
      progressSeverity[progressSeverity.length - 1].medium
        ? progressSeverity[progressSeverity.length - 1].medium
        : (progressSeverity[progressSeverity.length - 1].medium = 0);
      progressSeverity[progressSeverity.length - 1].low
        ? progressSeverity[progressSeverity.length - 1].low
        : (progressSeverity[progressSeverity.length - 1].low = 0);
      core.warning(
        "\n" +
          "Critical : " +
          progressSeverity[progressSeverity.length - 1].critical +
          "\n" +
          "High : " +
          progressSeverity[progressSeverity.length - 1].high +
          "\n" +
          "Medium : " +
          progressSeverity[progressSeverity.length - 1].medium +
          "\n" +
          "Low : " +
          progressSeverity[progressSeverity.length - 1].low +
          "\n"
      );

      const newIssues = await newIssue(repoName, token, ctServer);
      const weaknessIsKeywords = output.weakness_is.split(",");
      const weaknessIsCount = findWeaknessTitles(newIssues, weaknessIsKeywords);

      if (output.condition === "OR") {
        if (
          output.max_number_of_critical &&
          output.max_number_of_critical <
            progressSeverity[progressSeverity.length - 1].critical
        ) {
          core.setFailed("!! FAILED_ARGS : Critical limit exceeded -- ");
          scanProcess.data.state === "end";
          cancellation = true;
        } else if (
          output.max_number_of_critical &&
          output.max_number_of_high <
            progressSeverity[progressSeverity.length - 1].high
        ) {
          core.setFailed("!! FAILED_ARGS : High limit exceeded -- ");
          scanProcess.data.state === "end";
          cancellation = true;
        } else if (weaknessIsCount.length > 0) {
          core.setFailed(
            "!! FAILED_ARGS : Weaknesses entered in the weakness_is key were found during the scan."
          );
          scanProcess.data.state === "end";
        }
      } else if (output.condition === "AND") {
        if (
          (output.max_number_of_critical &&
            output.max_number_of_critical <
              progressSeverity[progressSeverity.length - 1].critical) ||
          (output.max_number_of_critical &&
            output.max_number_of_high <
              progressSeverity[progressSeverity.length - 1].high) ||
          weaknessIsCount.length > 0
        ) {
          core.setFailed(
            "!! FAILED ARGS : Not all conditions are met according to the given arguments"
          );
          scanProcess.data.state === "end";
          cancellation = true;
        }
      }
    }
    if (scanProcess.data.state === "end" || cancellation) {
      await resultScan(
        scanProcess.data.riskscore,
        scanProcess.data.started_at,
        scanProcess.data.ended_at,
        scanProcess.data.severities
      );
    } else {
      setTimeout(function () {
        awaitScan(sid);
      }, 3000);
    }
  } catch (error) {
    core.setFailed(error.message);
  }
};
const resultScan = async (riskS, started_at, ended_at, totalSeverities) => {
  try {
    let reason;
    if (!cancellation) {
      reason = `Scan Completed... %${progressData[progressData.length - 1]}`;
    } else {
      reason =
        "Pipeline interrupted because the FAILED_ARGS arguments you entered were found... ";
    }

    let totalSev = {
      critical: totalSeverities.critical ? totalSeverities.critical : 0,
      high: totalSeverities.high ? totalSeverities.high : 0,
      medium: totalSeverities.medium ? totalSeverities.medium : 0,
      low: totalSeverities.low ? totalSeverities.low : 0,
    };

    core.warning(
      "\n" +
        "Result : " +
        reason +
        "\n" +
        "Critical : " +
        totalSev.critical +
        "\n" +
        "High : " +
        totalSev.high +
        "\n" +
        "Medium : " +
        totalSev.medium +
        "\n" +
        "Low : " +
        totalSev.low +
        "\n"
    );

    const newIssues = await newIssue(repoName, token, ctServer);
    const allIssues = await allIssue(repoName, token, ctServer);

    let durationTime = convertToHHMMSS(ended_at, started_at);
    const riskscore = getScore(riskS);

    const newIssuesData = countAndGroupByTitle(newIssues);
    const newIssuesSeverity = countBySeverity(newIssuesData);
    const allIssuesData = countAndGroupByTitle(allIssues);
    const allIssuesSeverity = countBySeverity(allIssuesData);

    let totalCountNewIssues = 0;
    for (const obj of newIssuesData) {
      totalCountNewIssues += obj.count;
    }

    let html = htmlCode(
      totalCountNewIssues,
      newIssuesSeverity,
      allIssuesData,
      durationTime,
      riskS,
      riskscore,
      totalSeverities,
      repoName,
      ctServer
    );

    if (pr && pr.number) {
      if (allIssues.length === 0) {
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
              body: html,
            });
          } catch (error) {
            core.setFailed(error.message);
          }
        }
      } else {
        const weaknessIsKeywords = output.weakness_is.split(",");
        const weaknessIsCount = findWeaknessTitles(
          allIssues,
          weaknessIsKeywords
        );
        if (output.condition === "OR") {
          if (
            output.max_number_of_critical &&
            output.max_number_of_critical < totalSeverities?.critical
          ) {
            try {
              await octokit.pulls.update({
                owner: repoOwner,
                repo: repoName,
                pull_number: pr.number,
                state: "COMMENT",
                body: html,
              });
              core.setFailed("!! FAILED_ARGS : Critical limit exceeded -- ");
            } catch (error) {
              core.setFailed(error.message);
            }
          } else if (
            output.max_number_of_critical &&
            output.max_number_of_high < totalSeverities?.high
          ) {
            try {
              await octokit.pulls.update({
                owner: repoOwner,
                repo: repoName,
                pull_number: pr.number,
                state: "COMMENT",
                body: html,
              });
              core.setFailed("!! FAILED_ARGS : High limit exceeded -- ");
            } catch (error) {
              core.setFailed(error.message);
            }
          } else if (weaknessIsCount.length > 0) {
            try {
              await octokit.pulls.update({
                owner: repoOwner,
                repo: repoName,
                pull_number: pr.number,
                state: "COMMENT",
                body: html,
              });
              core.setFailed(
                "!! FAILED_ARGS : Weaknesses entered in the weakness_is key were found during the scan."
              );
            } catch (error) {
              core.setFailed(error.message);
            }
          } else {
            try {
              await octokit.pulls.update({
                owner: repoOwner,
                repo: repoName,
                pull_number: pr.number,
                state: "COMMENT",
                body: html,
              });
              core.setFailed(
                "!! A condition you entered in FAILED_ARGS was not found, but there are findings from the scan."
              );
            } catch (error) {
              core.setFailed(error.message);
            }
          }
        } else if (output.condition === "AND") {
          if (
            (output.max_number_of_critical &&
              output.max_number_of_critical < totalSeverities?.critical) ||
            (output.max_number_of_critical &&
              output.max_number_of_high < totalSeverities?.high) ||
            weaknessIsCount.length > 0
          ) {
            try {
              await octokit.pulls.update({
                owner: repoOwner,
                repo: repoName,
                pull_number: pr.number,
                state: "COMMENT",
                body: html,
              });
              core.setFailed(
                "!! FAILED ARGS : Not all conditions are met according to the given arguments"
              );
            } catch (error) {
              core.setFailed(error.message);
            }
          } else {
            try {
              await octokit.pulls.update({
                owner: repoOwner,
                repo: repoName,
                pull_number: pr.number,
                state: "COMMENT",
                body: html,
              });
              core.setFailed(
                "!! A condition you entered in FAILED_ARGS was not found, but there are findings from the scan."
              );
            } catch (error) {
              core.setFailed(error.message);
            }
          }
        }
      }
    }
  } catch (error) {
    core.setFailed(error.message);
  }
};

(async () => {
  const start = await startScan();
  await awaitScan(start.data.scan_id);
})();
