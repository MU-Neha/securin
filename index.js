import express from "express";
import bodyParser from "body-parser";
import axios from "axios";
import { MongoClient } from "mongodb";

const app = express();
const port = 3000;
let db;
async function go() {
  const client = new MongoClient(
    "mongodb+srv://cvb_user:AvCRRxR5AsDD7YkR@cluster0.43pbyrl.mongodb.net/CVEDB?retryWrites=true&w=majority&appName=cluster0"
  );
  client.connect();
  db = client.db();
  app.listen(port, () => {
    console.log(`Server running on port: ${port}`);
  });
}

go();

async function loadData() {
  
  let result = await db
    .collection("DATALOADING")
    .updateOne({}, { $set: { isLoading: true } });
  
  console.log(
    `Updated isLoading to true - ${result.modifiedCount} document(s) was/were updated.`
  );

  let currentCount = await db.collection("CVES").count();
  let startIndex = currentCount;

  console.log(
    `Fetching data - https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=2000&startIndex=${startIndex}`
  );

  let response = await axios.get(
    `https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=2000&startIndex=${startIndex}`
  );

  const cves = response.data.vulnerabilities;
  const totalRecords = response.data.totalResults;

  for(let i=0; i<5; i++) {
    cves.forEach(async (element) => {

      let id;
      let sourceIdentifier;
      let published;
      let modified;
      let status;
      let description; 
      let severity;
      let score;
      let vectorString;
      let accessVector;
      let accessComplexity;
      let authentication;
      let confidentialityImpact;
      let integrityImpact;
      let availabilityImpact;
      let exploitabilityScore;
      let impactScore;
      let cpe;
      
      if ("cve" in element) {
        id = element.cve.id;
        sourceIdentifier = element.cve.sourceIdentifier;
        published = element.cve.published;
        modified = element.cve.lastModified;
        status = element.cve.vulnStatus;

        if ("descriptions" in element.cve) {
          description = element.cve.descriptions[0].value;
        }

        if ("metrics" in element.cve) {
          if ("cvssMetricV2" in element.cve.metrics) {
            severity = element.cve.metrics.cvssMetricV2[0].baseSeverity;
            score = element.cve.metrics.cvssMetricV2[0].cvssData.baseScore;
            vectorString = element.cve.metrics.cvssMetricV2[0].cvssData.vectorString;
            accessVector = element.cve.metrics.cvssMetricV2[0].cvssData.accessVector;
            accessComplexity = element.cve.metrics.cvssMetricV2[0].cvssData.accessComplexity;
            authentication = element.cve.metrics.cvssMetricV2[0].cvssData.authentication;
            confidentialityImpact = element.cve.metrics.cvssMetricV2[0].cvssData.confidentialityImpact;
            integrityImpact = element.cve.metrics.cvssMetricV2[0].cvssData.integrityImpact;
            availabilityImpact = element.cve.metrics.cvssMetricV2[0].cvssData.availabilityImpact;
            exploitabilityScore = element.cve.metrics.cvssMetricV2[0].exploitabilityScore;
            impactScore = element.cve.metrics.cvssMetricV2[0].impactScore;
          }

          if ("configurations" in element.cve) {
            cpe = element.cve.configurations[0].nodes[0].cpeMatch;
          }
        }
      }

      
      let cve = {
          id: id,
          sourceIdentifier: sourceIdentifier,
          published: published,
          modified: modified,
          status: status,
          description: description,
          severity: severity,
          score: score,
          vectorString: vectorString,
          accessVector: accessVector,
          accessComplexity: accessComplexity,
          authentication: authentication,
          confidentialityImpact: confidentialityImpact,
          integrityImpact: integrityImpact,
          availabilityImpact: availabilityImpact,
          exploitabilityScore: exploitabilityScore,
          impactScore: impactScore,
          cpe: cpe,
        };

      const idToFind = element.cve.id;
      result = await db.collection("CVES").findOne({ id: idToFind });
      
      if (result != null) {
          console.log(`DUPLICATE: ${element.cve.id}`);
          console.log(result);
      } else {
          await db.collection("CVES").insertOne(cve);
          console.log(`INSERTED - ${element.cve.id}`);
      }

    });
  };

  result = await db
    .collection("DATALOADING")
    .updateOne({}, { $set: { isLoading: false } });
  console.log(
    `Updated isLoading to false - ${result.modifiedCount} document(s) was/were updated.`
  );
}

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

//ROOT PATH - GET

app.get("/", async (req, res) => {
  try {
    let currentCount = await db.collection("CVES").count();
    let response = await axios.get(
      `https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=1&startIndex=0`
    );

    const totalRec = response.data.totalResults;

    let result = {
      count: currentCount,
      totalRec: totalRec,
      remainingRec: totalRec - currentCount,
      endRec: currentCount - 1,
    };

    res.render("index.ejs", { data: result });
  } catch (error) {
    console.error("Failed to get count from database:", error.message);
    res.render("index.ejs", {
      error: error.message,
    });
  }
});

//POST FROM ROOT PATH - TO CLEAN DATA / LOAD DATA

app.post("/loadData", async (req, res) => {
  try {
    console.log(req.body);
    let startIndex = JSON.parse(req.body.startIndex);

    //If startIndex == 0, we clean existing data
    //else we load data

    if (startIndex == 0) {
      console.log("Cleaning database");
      await db.collection("CVES").deleteMany({});
      console.log("Cleaned...");
    } else {
      loadData();
    }

    let currentCount = await db.collection("CVES").count();
    let response = await axios.get(
      `https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=1&startIndex=0`
    );

    const totalRec = response.data.totalResults;

    let result = {
      count: currentCount,
      totalRec: totalRec,
      remainingRec: totalRec - currentCount,
      endRec: currentCount - 1,
    };

    res.render("index.ejs", { data: result });
  } catch (error) {
    console.error("Failed to make request:", error.message);
    res.render("index.ejs", {
      error: "No activities that match your criteria.",
    });
  }
});

//GET LIST OF CVEs

app.get("/cves/list", async (req, res) => {
  try {
    let startIndex = 0;
    let recordsPerPage = 10;
    const currentCount = await db.collection("CVES").count();
    const query = {};
    const options = {
      sort: { published: 1 },
      skip: startIndex,
      limit: recordsPerPage,
    };

    const cursor = await db.collection("CVES").find(query, options);

    const cves = await cursor.toArray();
    const result = {
      startIndex: startIndex,
      recordsPerPage: recordsPerPage,
      totalRecords: currentCount,
      cves: cves,
    };
    res.render("cveList.ejs", { data: result });
    // console.log(result);
  } catch (error) {
    console.error("Failed to make request:", error.message);
    res.render("cveList.ejs", {
      error: error.message,
    });
  }
});

//POST - LIST OF CVEs - HANDLE PAGINATION, FILTER

app.post("/cves/list", async (req, res) => {
  try {
    console.log(req.body);

    let recordsPerPage = JSON.parse(req.body.recordsPerPage);
    let startIndex = JSON.parse(req.body.startIndex);

    const currentCount = await db.collection("CVES").count();

    let query = {};
    const options = {
      sort: { published: 1 },
      skip: startIndex,
      limit: recordsPerPage,
    };

    let cursor = await db.collection("CVES").find(query, options);

    if ("filterCveId" in req.body) {
      query={id: req.body.filterCveId};
      cursor = await db.collection("CVES").find(query, {});
    } 
    else if ("filterCveYear" in req.body) {
      let filtYear = JSON.parse(req.body.filterCveYear);
      let prevYear = (filtYear-1)+"-12-31T14:56:59.301Z";
      let thisYear = (filtYear)+"-12-31T14:56:59.301Z";

      console.log(prevYear);
      console.log(thisYear);

      query={
        "published": {
            $gte: new Date(prevYear),
            $lt: new Date(thisYear)
        }
      }
      cursor = await db.collection("CVES").find(query, {});
    } 

    const cves = await cursor.toArray();
    console.log(cves);
    const result = {
      startIndex: startIndex,
      recordsPerPage: recordsPerPage,
      totalRecords: currentCount,
      cves: cves,
    };
    res.render("cveList.ejs", { data: result });
  } catch (error) {
    console.error("Failed to make request:", error.message);
    res.render("cveList.ejs", {
      error: error.message,
    });
  }
});

//GET - ONE CVE

app.get("/cves/:id", async (req, res) => {
  try {
    const idToFind = req.params.id;
    const result = await db.collection("CVES").findOne({ id: idToFind });
    res.render("cve.ejs", { data: result });
    console.log(result);
  } catch (error) {
    console.error("Failed to make request:", error.message);
    res.render("cve.ejs", {
      error: error.message,
    });
  }
});
