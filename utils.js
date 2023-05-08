const axios = require("axios");

const countAndGroupByTitle = (arr) => {
  const result = [];
  arr.forEach((obj) => {
    const title = obj.issue_state.weakness_id;
    const severity = obj.issue_state.severity;
    if (!result.find((o) => o.title === title)) {
      result.push({
        title: title,
        count: 1,
        severity: severity,
      });
    } else {
      const item = result.find((o) => o.title === title);
      item.count++;
    }
  });
  return result;
};

const convertToHHMMSS = (endedAt, startedAt) => {
  let durationInMilliseconds = endedAt - startedAt;
  let durationInMinutes = durationInMilliseconds / (1000 * 60);
  let hours = Math.floor(durationInMinutes / 60);
  let minutes = Math.floor(durationInMinutes % 60);
  let seconds = Math.floor((durationInMilliseconds % (1000 * 60)) / 1000);
  return (
    hours.toString().padStart(2, "0") +
    ":" +
    minutes.toString().padStart(2, "0") +
    ":" +
    seconds.toString().padStart(2, "0")
  );
};

const scores = [
  {
    score: "A+",
    startingPerc: 97,
    endingPerc: 100,
    color: "#109146",
  },
  {
    score: "A",
    startingPerc: 93,
    endingPerc: 96,
    color: "#109146",
  },
  {
    score: "A-",
    startingPerc: 90,
    endingPerc: 92,
    color: "#7DBC41",
  },
  {
    score: "B+",
    startingPerc: 87,
    endingPerc: 89,
    color: "#7DBC41",
  },
  {
    score: "B",
    startingPerc: 83,
    endingPerc: 86,
    color: "#7DBC41",
  },
  {
    score: "B-",
    startingPerc: 80,
    endingPerc: 82,
    color: "#FFCC06",
  },
  {
    score: "C+",
    startingPerc: 77,
    endingPerc: 79,
    color: "#FFCC06",
  },
  {
    score: "C",
    startingPerc: 73,
    endingPerc: 76,
    color: "#FFCC06",
  },
  {
    score: "C-",
    startingPerc: 70,
    endingPerc: 72,
    color: "#F58E1D",
  },
  {
    score: "D+",
    startingPerc: 67,
    endingPerc: 69,
    color: "#F58E1D",
  },
  {
    score: "D",
    startingPerc: 63,
    endingPerc: 66,
    color: "#EF4722",
  },
  {
    score: "D-",
    startingPerc: 60,
    endingPerc: 62,
    color: "#EF4722",
  },
  {
    score: "F",
    startingPerc: 0,
    endingPerc: 59,
    color: "#BD2026",
  },
];

const getScore = (percentage) => {
  for (let i = 0; i < scores.length; i++) {
    if (
      percentage >= scores[i].startingPerc &&
      percentage <= scores[i].endingPerc
    ) {
      return scores[i];
    }
  }
};

const countBySeverity = (arr) => {
  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  for (const obj of arr) {
    if (obj.severity) {
      counts[obj.severity] += obj.count;
    }
  }
  return counts;
};

const htmlCode = (
  totalCountNewIssue,
  newIssuesSeverity,
  allIssuesData,
  durationTime,
  rs,
  riskscore,
  totalSeverities,
  repoName,
  ctServer
) => {
  let html = "";

  html += "<body>";
  html += "<h2>Result</h2>";

  let table = '<table border="1">';
  table += "<tr><th>Weakness</th><th>Total Issue</th><th>New Issue</th></tr>";

  const total = Object.values(totalSeverities).reduce((a, b) => a + b, 0);

  table += `<tr><td><em>🔴 Critical</em></td><td>${
    totalSeverities?.critical ? totalSeverities?.critical : 0
  }</td><td>${newIssuesSeverity.critical}</td></tr>`;

  table += `<tr><td><em>🟠 High</em></td><td>${
    totalSeverities?.high ? totalSeverities?.high : 0
  }</td><td>${newIssuesSeverity.high}</td></tr>`;

  table += `<tr><td><em>🟡 Medium</em></td><td>${
    totalSeverities?.medium ? totalSeverities?.medium : 0
  }</td><td>${newIssuesSeverity.medium}</td></tr>`;

  table += `<tr><td><em>🔵 Low</em></td><td>${
    totalSeverities?.low ? totalSeverities?.low : 0
  }</td><td>${newIssuesSeverity.low}</td></tr>`;

  table += `<tr><td><em>🔘 TOTAL </em></td><td>${total}</td><td>${totalCountNewIssue}</td></tr>`;

  table += "</table>";

  html += table;
  html += `<h2>Weaknesses</h2>`;

  html += "<ul>";
  let weaknesslist = "";
  allIssuesData.map((r) => {
    const severityCapitalize =
      r.severity.charAt(0).toUpperCase() + r.severity.slice(1);

    const query = {
      projectName: repoName,
      issuename: r.title,
    };
    const encodedQ = btoa(unescape(encodeURIComponent(JSON.stringify(query))));

    var listItem =
      "<li>" +
      `<a href=${ctServer}/issues?q=${encodedQ}>` +
      "🔲 " +
      r.title +
      " -> " +
      severityCapitalize +
      "(" +
      r.count +
      ")" +
      "</a>" +
      "</li>";
    weaknesslist += listItem;
  });
  html += weaknesslist;
  html += "</ul>";

  html += `<p>⏳ Scan Duration: ${durationTime}</p>`;
  html += `<p>❗ Risk Score: ${rs} -> ${riskscore.score}</p>`;
  html += "</body>";

  return html;
};

const findWeaknessTitles = (arr, keywords) => {
  const regexArray = keywords.map((str) => new RegExp(str));

  let failedWeaknesss = [];

  arr.forEach((element) => {
    const found = regexArray.find((r) => {
      return r.test(element.issue_state.weakness_id);
    });
    if (found) failedWeaknesss.push(element);
  });

  return failedWeaknesss;
};

const newIssue = async (repoName, token, ctServer) => {
  let newIssueResult;
  let query = {
    projectName: repoName,
    historical: ["New Issue"],
  };
  const encodedQ = btoa(unescape(encodeURIComponent(JSON.stringify(query))));
  newIssueResult = await axios.get(
    `${ctServer}/api/scanlog/issues?q=${encodedQ}&pageSize=500`,
    {
      headers: {
        Authorization: token,
        "x-ct-organization": "codethreat",
      },
    }
  );

  const xCtPager = JSON.parse(atob(newIssueResult.headers.get("x-ct-pager")));

  let allData = [];

  for (let i = 1; i <= xCtPager.pages; i++) {
    let response = await axios.get(
      `${ctServer}/api/scanlog/issues?q=${encodedQ}&pid=${xCtPager.id}&page=${i}`,
      {
        headers: {
          Authorization: token,
          "x-ct-organization": "codethreat",
        },
      }
    );
    allData.push(...response.data);
  }

  if (xCtPager.pages === 0) allData = newIssueResult.data;

  return allData;
};

const allIssue = async (repoName, token, ctServer) => {
  let allIssueResult;
  let query = {
    projectName: repoName,
  };
  const encodedQ = btoa(unescape(encodeURIComponent(JSON.stringify(query))));
  allIssueResult = await axios.get(
    `${ctServer}/api/scanlog/issues?q=${encodedQ}&pageSize=500`,
    {
      headers: {
        Authorization: token,
        "x-ct-organization": "codethreat",
      },
    }
  );

  const xCtPager = JSON.parse(atob(allIssueResult.headers.get("x-ct-pager")));

  let allData = [];

  for (let i = 1; i <= xCtPager.pages; i++) {
    let response = await axios.get(
      `${ctServer}/api/scanlog/issues?q=${encodedQ}&pid=${xCtPager.id}&page=${i}`,
      {
        headers: {
          Authorization: token,
          "x-ct-organization": "codethreat",
        },
      }
    );
    allData.push(...response.data);
  }

  if (xCtPager.pages === 0) allData = allIssueResult.data;

  return allData;
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
      },
    ) => {
      return {
        ...acc,
        max_number_of_critical: max_number_of_critical ||
          acc.max_number_of_critical,
        max_number_of_high: max_number_of_high || acc.max_number_of_high,
        weakness_is: weakness_is || acc.weakness_is,
        automerge: automerge || acc.automerge,
        condition: condition || acc.condition,
      };
    },
    {},
  );
  return output;
}


module.exports = {
  countAndGroupByTitle,
  convertToHHMMSS,
  getScore,
  countBySeverity,
  htmlCode,
  findWeaknessTitles,
  newIssue,
  allIssue,
  failedArgs,
};