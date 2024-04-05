const axios = require("axios");
const fs = require('fs').promises;

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
    safeRegexPattern.test(weakness)
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
        sync_scan
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
    throw new Error(error.response.data.message);
  }
  console.log("Login successful")
  return responseToken.data.access_token;
};

const check = async (ctServer, repoName, authToken, orgname) => {
  let checkProject;
  try {
    checkProject = await axios.get(`${ctServer}/api/project?key=${repoName}`, {
      headers: {
        Authorization: authToken,
        "x-ct-organization": orgname,
      },
    });
  } catch (error) {
    if (error.response.data.code === 404 || error.response.data.code === 400) {
      return {
        type: null,
      };
    }
  }
  if (checkProject.data.type !== "github") {
    throw new Error(
      "There is a project with this name, but its type is not github."
    );
  }
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
    throw new Error(error.response.data.message);
  }
  console.log("Project Created.")
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
  policyName,
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
        // policy_id: policyName,
      },
      {
        headers: {
          Authorization: authToken,
          "x-ct-organization": orgname,
        },
      }
    );
  } catch (error) {
    throw new Error(error.response.data.message);
  }
  return scanStart;
};

const status = async (ctServer, sid, authToken, orgname) => {
  let scanProcess;
  try {
    scanProcess = await axios.get(`${ctServer}/api/scan/status/${sid}`, {
      headers: {
        Authorization: authToken,
        "x-ct-organization": orgname,
        "plugin": true,
      },
    });
  } catch (error) {
    throw new Error(error.response.data.message);
  }
  severityLevels.forEach((level) => {
    severities[level] = scanProcess.data.severities?.[level] || 0;
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

const result = async (ctServer, sid, authToken, orgname, branch, project_name) => {
  let resultScan;
  try {
    resultScan = await axios.get(`${ctServer}/api/plugins/helper?sid=${sid}&branch=${branch}&project_name=${project_name}`, {
      headers: {
        Authorization: authToken,
        "x-ct-organization": orgname,
        "x-ct-from": 'github'
      },
    });
  } catch (error) {
    throw new Error(error.response.data.message);
  }
  return {report: resultScan.data.report, scaSeverityCounts: resultScan.data.scaSeverityCounts};
}

const saveSarif = async (ctServer, sid, authToken, orgname) => {
  try {
    const response = await axios.get(`${ctServer}/api/report/scan/create?sid=${sid}&reportType=sarif`, {
      headers: {
        Authorization: authToken,
        "x-ct-organization": orgname,
        "x-ct-from": 'github'
      },
    });

    await fs.writeFile('codethreat.sarif.json', JSON.stringify(response.data.parsedResult));

    console.log('SARIF report saved to codethreat.sarif.json');
  } catch (error) {
    throw new Error(`Failed to save SARIF report: ${error.response?.data?.message || error.message}`);
  }
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
  saveSarif
};
