const GITHUB_API = "https://api.github.com";
const TOKEN = import.meta.env.VITE_GITHUB_TOKEN;

export const getToken = () => TOKEN;

interface RepoFile {
  name: string;
  path: string;
  type: "file" | "dir";
  size?: number;
  download_url?: string;
}

interface GitHubRepo {
  owner: string;
  name: string;
  fullName: string;
  description?: string;
  stars: number;
  language?: string;
}

export const parseRepoUrl = (url: string): GitHubRepo | null => {
  const patterns = [
    /github\.com\/([^\/]+)\/([^\/]+)/,
    /^([^\/]+)\/([^\/]+)$/,
  ];
  
  for (const pattern of patterns) {
    const match = url.match(pattern);
    if (match) {
      return {
        owner: match[1],
        name: match[2].replace(/\.git$/, ""),
        fullName: `${match[1]}/${match[2].replace(/\.git$/, "")}`,
      };
    }
  }
  return null;
};

export const fetchRepoInfo = async (repo: GitHubRepo) => {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github.v3+json",
  };
  
  if (TOKEN) {
    headers.Authorization = `token ${TOKEN}`;
  }

  const res = await fetch(`${GITHUB_API}/repos/${repo.owner}/${repo.name}`, { headers });
  
  if (!res.ok) {
    if (res.status === 404) throw new Error("Repository not found");
    if (res.status === 403) throw new Error("Rate limited. Add a GitHub token.");
    throw new Error("Failed to fetch repository");
  }

  return res.json();
};

export const fetchRepoContents = async (repo: GitHubRepo, path: string = ""): Promise<RepoFile[]> => {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github.v3+json",
  };
  
  if (TOKEN) {
    headers.Authorization = `token ${TOKEN}`;
  }

  const res = await fetch(`${GITHUB_API}/repos/${repo.owner}/${repo.name}/contents/${path}`, { headers });
  
  if (!res.ok) {
    if (res.status === 404) return [];
    if (res.status === 403) throw new Error("Rate limited. Add a GitHub token.");
    throw new Error("Failed to fetch contents");
  }

  const data = await res.json();
  return Array.isArray(data) ? data : [data];
};

export const fetchFileContent = async (repo: GitHubRepo, path: string): Promise<string> => {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github.v3+json",
  };
  
  if (TOKEN) {
    headers.Authorization = `token ${TOKEN}`;
  }

  const res = await fetch(`${GITHUB_API}/repos/${repo.owner}/${repo.name}/contents/${path}`, { headers });
  
  if (!res.ok) {
    throw new Error("Failed to fetch file");
  }

  const data = await res.json();
  
  if (data.content) {
    return atob(data.content);
  }
  
  return "";
};