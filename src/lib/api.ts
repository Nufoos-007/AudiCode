export const auditApi = {
  async startAudit(repoUrl: string) {
    // POST /api/audit
    // return fetch('/api/audit', { method: 'POST', body: JSON.stringify({ repoUrl }) });
    console.log("API placeholder: POST /api/audit", { repoUrl });
    return { auditId: "mock-id" };
  },

  async getResults(auditId: string) {
    // GET /api/results?id=auditId
    // return fetch(`/api/results?id=${auditId}`);
    console.log("API placeholder: GET /api/results", { auditId });
    return null;
  },
};
