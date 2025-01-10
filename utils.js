const axios = require("axios");
const fs = require("fs").promises;

const {
  checkLower1_7_8,
  checkUpper1_7_8,
  compareVersions,
} = require("./adapter");

let apiVersion;

const severityLevels = ["critical", "high", "medium", "low"];

let severities = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
};

const findWeaknessTitles = (weaknessArray, keywords) => {
  const sanitizedKeywords = [];

  keywords.forEach((keyword) => {
    const sanitizedKeyword = keyword.replace(/[^a-zA-Z0-9.,]/g, "");
    if (sanitizedKeyword) {
      sanitizedKeywords.push(sanitizedKeyword);
    }
  });

  const safeRegexPattern = new RegExp(sanitizedKeywords.join("|"), "i");
  const found = weaknessArray.filter((weakness) =>
    safeRegexPattern.test(weakness.weakness_id)
  );

  return found;
};

const failedArgs = (failedArgsParsed) => {
  const output = failedArgsParsed.reduce(
    (
      acc,
      {
        max_number_of_critical,
        max_number_of_high,
        weakness_is,
        automerge,
        condition,
        sync_scan,
      }
    ) => {
      return {
        ...acc,
        max_number_of_critical:
          max_number_of_critical || acc.max_number_of_critical,
        max_number_of_high: max_number_of_high || acc.max_number_of_high,
        weakness_is: weakness_is || acc.weakness_is,
        automerge: automerge || acc.automerge,
        condition: condition || acc.condition,
        sync_scan: sync_scan || acc.sync_scan,
      };
    },
    {}
  );
  return output;
};

const login = async (ctServer, username, password) => {
  let responseToken;
  try {
    responseToken = await axios.post(`${ctServer}/api/signin`, {
      client_id: username,
      client_secret: password,
    });
  } catch (error) {
    if (error.response && error.response.data) {
      throw new Error(JSON.stringify(error.response.data));
    } else {
      throw new Error(error);
    }
  }
  console.log("[CodeThreat]: Login successful");
  if (responseToken.headers["x-api-version"]) {
    apiVersion = responseToken.headers["x-api-version"];
    console.log(`[CodeThreat]: Api Version: ${apiVersion}`);
  }

  return responseToken.data.access_token;
};

const getOrg = async (ctServer, token, orgname) => {
  let response;
  try {
    response = await axios.get(`${ctServer}/api/organization?key=${orgname}`, {
      headers: {
        Authorization: token,
        "x-ct-organization": orgname,
      },
    });
  } catch (error) {
    if (error.response && error.response.data) {
      throw new Error(JSON.stringify(error.response.data));
    } else {
      throw new Error(error);
    }
  }
  if (response.headers["x-api-version"]) {
    apiVersion = response.headers["x-api-version"];
    console.log(`[CodeThreat]: Api Version: ${apiVersion}`);
  }
};

const check = async (ctServer, repoName, authToken, orgname) => {
  let checkProject;
  const compareVersion = compareVersions("1.7.8", apiVersion);
  if (compareVersion === 1)
    checkProject = await checkLower1_7_8(
      ctServer,
      repoName,
      authToken,
      orgname
    );
  else if (compareVersion === -1)
    checkProject = await checkUpper1_7_8(
      ctServer,
      repoName,
      authToken,
      orgname
    );

  return checkProject;
};

const create = async (
  ctServer,
  repoName,
  branch,
  repoOwner,
  type,
  githubtoken,
  repoId,
  authToken,
  orgname,
  policyName
) => {
  let createProject;
  try {
    createProject = await axios.post(
      `${ctServer}/api/integration/github/set`,
      {
        repoId: `${repoName}:${repoId}`,
        project: repoName,
        branch: branch,
        account: repoOwner,
        action: true,
        type,
        githubtoken,
      },
      {
        headers: {
          Authorization: authToken,
          "x-ct-organization": orgname,
        },
      }
    );
  } catch (error) {
    if (error.response && error.response.data) {
      throw new Error(JSON.stringify(error.response.data));
    } else {
      throw new Error(error);
    }
  }
  console.log("Project Created.");
  return createProject;
};

const start = async (
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
  policyName
) => {
  let scanStart;
  try {
    scanStart = await axios.post(
      `${ctServer}/api/integration/github/start`,
      {
        project: repoName,
        branch: branch,
        account: repoOwner,
        id: repoId,
        action: true,
        commitId,
        committer,
        commitMessage,
        type,
        githubtoken,
        policy_id: policyName,
      },
      {
        headers: {
          Authorization: authToken,
          "x-ct-organization": orgname,
        },
      }
    );
    if (scanStart.status === 200 && scanStart.data.scan_id) return scanStart;
    else {
      console.log(
        `Failed to start scan. Status: ${JSON.stringify(
          scanStart.status
        )} Error: ${JSON.stringify(
          scanStart.data || { error: "Unexpected Error: Scan Start" }
        )}`
      );
      throw new Error(
        JSON.stringify(
          scanStart.data || { error: "Unexpected Error: Scan Start" }
        )
      );
    }
  } catch (error) {
    if (error.response && error.response.data)
      throw new Error(JSON.stringify(error.response.data));
    else throw new Error(error);
  }
};

const status = async (ctServer, sid, authToken, orgname) => {
  let scanProcess;
  try {
    scanProcess = await axios.get(`${ctServer}/api/scan/status/${sid}`, {
      headers: {
        Authorization: authToken,
        "x-ct-organization": orgname,
        plugin: true,
      },
    });
  } catch (error) {
    if (error.response && error.response.data) {
      throw new Error(JSON.stringify(error.response.data));
    } else {
      throw new Error(error);
    }
  }
  severityLevels.forEach((level) => {
    severities[level] = scanProcess.data.sast_severities?.[level] || 0;
  });
  return {
    progress: scanProcess.data.progress_data.progress,
    weaknessesArr: scanProcess.data.weaknessesArr,
    state: scanProcess.data.state,
    riskscore: scanProcess.data.riskscore,
    started_at: scanProcess.data.started_at,
    ended_at: scanProcess.data.ended_at,
    severities,
  };
};

const result = async (
  ctServer,
  sid,
  authToken,
  orgname,
  branch,
  project_name
) => {
  let resultScan;
  try {
    resultScan = await axios.get(
      `${ctServer}/api/plugins/helper?sid=${sid}&branch=${branch}&project_name=${project_name}`,
      {
        headers: {
          Authorization: authToken,
          "x-ct-organization": orgname,
          "x-ct-from": "github",
        },
      }
    );
  } catch (error) {
    if (error.response.status === 404) return { type: null };
    throw new Error(error.response.data.message);
  }
  return {
    report: resultScan.data.report,
    scaSeverityCounts: resultScan.data.scaSeverityCounts,
  };
};

const saveSarif = async (
  ctServer,
  sid,
  authToken,
  orgname,
  projectName,
  branch
) => {
  try {
    const response = await axios.get(
      `${ctServer}/api/report/scan/create?sid=${sid}&projectName=${projectName}&branch=${branch}&reportType=sarif`,
      {
        headers: {
          Authorization: authToken,
          "x-ct-organization": orgname,
          "x-ct-from": "github",
        },
      }
    );

    await fs.writeFile(
      "codethreat.sarif.json",
      JSON.stringify(response.data.parsedResult)
    );

    console.log("[CodeThreat]: SARIF report saved to codethreat.sarif.json");
  } catch (error) {
    throw new Error(
      `Failed to save SARIF report: ${
        error.response?.data?.message || error.message
      }`
    );
  }
};

const getEnvVars = () => {
  const token = process.env.ACCESS_TOKEN;
  const ctServer = (process.env.CT_SERVER || '').trim().replace(/\/+$/, '');
  const githubtoken = process.env.GITHUB_TOKEN;
  const username = process.env.USERNAME;
  const password = process.env.PASSWORD;
  const orgname = process.env.ORGNAME;

  return {
    token,
    ctServer,
    githubtoken,
    username,
    password,
    orgname
  };
};

module.exports = {
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
};
