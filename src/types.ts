/**
 * Shared Type Definitions for AudiCode Shell
 */

export interface GitHubUser {
  id: string;
  login: string;
  name: string | null;
  avatarUrl: string;
  accessToken: string;
  isSandbox?: boolean;
}

export interface Repository {
  id: string;
  name: string;
  owner: string;
  description: string;
  isPrivate: boolean;
  defaultBranch: string;
  url: string;
}

export interface UserSession {
  user: GitHubUser | null;
  isAuthenticated: boolean;
}
