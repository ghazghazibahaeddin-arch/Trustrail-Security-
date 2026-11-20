'use client';

import React, { useState } from 'react';
import { useTrustrail } from '@/lib/use-trustrail';
import { Project } from '@/lib/trustrail-store';
import { FolderGit2, Play, Plus, X, Settings, GitBranch } from 'lucide-react';

export function ProjectsView() {
  const { projects, runScan, scanGithubRepo, createProject, refreshAll, user } = useTrustrail();
  const [showAddForm, setShowAddForm] = useState(false);
  const [showGithubImport, setShowGithubImport] = useState(false);
  const [githubSlug, setGithubSlug] = useState('');
  const [githubBranch, setGithubBranch] = useState('');
  const [name, setName] = useState('');
  const [repoUrl, setRepoUrl] = useState('');
  const [branch, setBranch] = useState('main');
  const [language, setLanguage] = useState('TypeScript');
  const [framework, setFramework] = useState('Next.js');

  const [scanTarget, setScanTarget] = useState<Project | null>(null);
  const [codeContent, setCodeContent] = useState('');
  const [packageJsonContent, setPackageJsonContent] = useState('');
  const [terraformContent, setTerraformContent] = useState('');
  const [dockerfileContent, setDockerfileContent] = useState('');

  const [editingProj, setEditingProj] = useState<Project | null>(null);
  const [editBranch, setEditBranch] = useState('main');
  const [editOwner, setEditOwner] = useState('');
  const [editSlsa, setEditSlsa] = useState<Project['slsaLevel']>('None');

  const handleAddProject = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || !repoUrl.trim()) return;
    await createProject({ name, repoUrl, branch, language, framework });
    setName('');
    setRepoUrl('');
    setShowAddForm(false);
  };

  const handleGithubImport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!githubSlug.trim()) return;
    const res = await scanGithubRepo(githubSlug.trim(), githubBranch.trim() || undefined);
    if (res) {
      setGithubSlug('');
      setGithubBranch('');
      setShowGithubImport(false);
    }
  };

  const handleCustomScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!scanTarget) return;
    await runScan({
      projectId: scanTarget.id,
      projectName: scanTarget.name,
      codeContent: codeContent.trim() || undefined,
      packageJsonContent: packageJsonContent.trim() || undefined,
      terraformContent: terraformContent.trim() || undefined,
      dockerfileContent: dockerfileContent.trim() || undefined,
    });
    setScanTarget(null);
    setCodeContent('');
    setPackageJsonContent('');
    setTerraformContent('');
    setDockerfileContent('');
  };

  const handleSaveSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingProj) return;
    await fetch(`/api/v1/projects/${encodeURIComponent(editingProj.id)}`, {
      method: 'PATCH',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ branch: editBranch, owner: editOwner, slsaLevel: editSlsa }),
    });
    await refreshAll();
    setEditingProj(null);
  };

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <FolderGit2 className="w-5 h-5 text-cyan-500" />
              <span>Projects & Repositories</span>
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Import live GitHub repositories or submit source code, package.json, Terraform plans, and Dockerfiles for real SAST, Secret, SCA/SBOM, and IaC scans.
            </p>
          </div>
          {user?.role !== 'Viewer' && (
            <div className="flex flex-wrap items-center gap-2 shrink-0">
              <button
                type="button"
                onClick={() => {
                  setShowGithubImport(!showGithubImport);
                  setShowAddForm(false);
                }}
                className="flex items-center space-x-1.5 px-3.5 py-2 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-900 dark:text-white text-xs font-semibold transition whitespace-nowrap"
              >
                <GitBranch className="w-3.5 h-3.5 text-cyan-500" />
                <span>Import GitHub Repo</span>
              </button>
              <button
                type="button"
                onClick={() => {
                  setShowAddForm(!showAddForm);
                  setShowGithubImport(false);
                }}
                className="flex items-center space-x-1.5 px-3.5 py-2 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-900 dark:text-white text-xs font-semibold transition whitespace-nowrap"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Add Project</span>
              </button>
              <button
                type="button"
                onClick={() => runScan()}
                className="flex items-center space-x-1.5 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition whitespace-nowrap"
              >
                <Play className="w-3.5 h-3.5 fill-white" />
                <span>Sweep All</span>
              </button>
            </div>
          )}
        </div>

        {showGithubImport && (
          <form
            onSubmit={handleGithubImport}
            className="bg-slate-50 dark:bg-slate-950 border border-cyan-500/30 rounded-xl p-5 mb-6 grid grid-cols-1 md:grid-cols-4 gap-3 items-end"
          >
            <div className="md:col-span-2">
              <label className="text-[10px] font-mono text-slate-500 uppercase">GitHub Repository (owner/repo or URL)</label>
              <input
                type="text"
                required
                value={githubSlug}
                onChange={(e) => setGithubSlug(e.target.value)}
                placeholder="expressjs/express"
                className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs font-mono mt-1"
              />
            </div>
            <div>
              <label className="text-[10px] font-mono text-slate-500 uppercase">Branch (Optional)</label>
              <input
                type="text"
                value={githubBranch}
                onChange={(e) => setGithubBranch(e.target.value)}
                placeholder="main"
                className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs font-mono mt-1"
              />
            </div>
            <button
              type="submit"
              className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition whitespace-nowrap"
            >
              Fetch &amp; Scan Live
            </button>
          </form>
        )}

        {showAddForm && (
          <form
            onSubmit={handleAddProject}
            className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-5 mb-6 grid grid-cols-1 md:grid-cols-5 gap-3 items-end"
          >
            <div>
              <label className="text-[10px] font-mono text-slate-500 uppercase">Project Name</label>
              <input
                type="text"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="checkout-api"
                className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs mt-1"
              />
            </div>
            <div className="md:col-span-2">
              <label className="text-[10px] font-mono text-slate-500 uppercase">Repository URL</label>
              <input
                type="text"
                required
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                placeholder="github.com/org/checkout-api"
                className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs mt-1"
              />
            </div>
            <div>
              <label className="text-[10px] font-mono text-slate-500 uppercase">Language</label>
              <input
                type="text"
                value={language}
                onChange={(e) => setLanguage(e.target.value)}
                className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs mt-1"
              />
            </div>
            <button
              type="submit"
              className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition"
            >
              Create Project
            </button>
          </form>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {projects.map((proj) => (
            <div
              key={proj.id}
              className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-5 flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center space-x-2 min-w-0">
                    <FolderGit2 className="w-4 h-4 text-cyan-500 shrink-0" />
                    <span className="text-sm font-bold text-slate-900 dark:text-white truncate">{proj.name}</span>
                  </div>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold shrink-0 ${
                      proj.status === 'protected'
                        ? 'bg-emerald-500/20 text-emerald-500'
                        : proj.status === 'warning'
                        ? 'bg-amber-500/20 text-amber-500'
                        : 'bg-rose-500/20 text-rose-500'
                    }`}
                  >
                    {proj.status.toUpperCase()}
                  </span>
                </div>
                <div className="text-xs text-slate-500 font-mono mb-3 truncate">
                  {proj.repoUrl} ({proj.branch})
                </div>

                <div className="grid grid-cols-4 gap-2 mb-4 text-center">
                  <div className="bg-white dark:bg-slate-900 p-2 rounded-lg border border-slate-200 dark:border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase">Critical</div>
                    <div className="text-sm font-bold text-rose-500 font-mono tabular-nums">{proj.findingsCount.critical}</div>
                  </div>
                  <div className="bg-white dark:bg-slate-900 p-2 rounded-lg border border-slate-200 dark:border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase">High</div>
                    <div className="text-sm font-bold text-amber-500 font-mono tabular-nums">{proj.findingsCount.high}</div>
                  </div>
                  <div className="bg-white dark:bg-slate-900 p-2 rounded-lg border border-slate-200 dark:border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase">Medium</div>
                    <div className="text-sm font-bold text-cyan-500 font-mono tabular-nums">{proj.findingsCount.medium}</div>
                  </div>
                  <div className="bg-white dark:bg-slate-900 p-2 rounded-lg border border-slate-200 dark:border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase">Low</div>
                    <div className="text-sm font-bold text-slate-500 font-mono tabular-nums">{proj.findingsCount.low}</div>
                  </div>
                </div>

                <div className="flex items-center justify-between text-xs text-slate-500 font-mono mb-4 pt-3 border-t border-slate-200 dark:border-slate-900">
                  <span>Owner: {proj.owner}</span>
                  <span>
                    SLSA: <strong className="text-cyan-600 dark:text-cyan-400">{proj.slsaLevel}</strong>
                  </span>
                </div>
              </div>

              {user?.role !== 'Viewer' && (
                <div className="flex items-center space-x-2 pt-3 border-t border-slate-200 dark:border-slate-900">
                  <button
                    type="button"
                    onClick={() => setScanTarget(proj)}
                    className="flex-1 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition"
                  >
                    Run Code / IaC Scan
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setEditingProj(proj);
                      setEditBranch(proj.branch);
                      setEditOwner(proj.owner);
                      setEditSlsa(proj.slsaLevel);
                    }}
                    className="px-3 py-2 rounded-lg bg-white dark:bg-slate-900 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 text-xs font-semibold transition border border-slate-200 dark:border-slate-800 flex items-center space-x-1"
                  >
                    <Settings className="w-3.5 h-3.5" />
                    <span>Settings</span>
                  </button>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Real Scan Artifact Modal */}
      {scanTarget && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <form
            onSubmit={handleCustomScan}
            className="w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4 max-h-[90vh] overflow-y-auto text-slate-100"
          >
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-sm font-bold text-white">Scan Artifacts for {scanTarget.name}</h3>
                <p className="text-xs text-slate-400">
                  Paste source code, package.json, Terraform HCL/Plan JSON, or Dockerfile to run real Trustrail engines.
                </p>
              </div>
              <button type="button" onClick={() => setScanTarget(null)} className="text-slate-400 hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div>
              <label className="text-[10px] font-mono text-slate-400 uppercase">Source Code (SAST + Secret Scanner)</label>
              <textarea
                rows={4}
                value={codeContent}
                onChange={(e) => setCodeContent(e.target.value)}
                placeholder={'const query = "SELECT * FROM users WHERE q=" + req.query.q;\nconst jwt_secret = "hardcoded-prod-secret-9988";'}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs font-mono text-slate-200 mt-1"
              />
            </div>
            <div>
              <label className="text-[10px] font-mono text-slate-400 uppercase">package.json (SCA + CycloneDX SBOM)</label>
              <textarea
                rows={3}
                value={packageJsonContent}
                onChange={(e) => setPackageJsonContent(e.target.value)}
                placeholder='{"name":"app","dependencies":{"lodash":"4.17.15"}}'
                className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs font-mono text-slate-200 mt-1"
              />
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="text-[10px] font-mono text-slate-400 uppercase">Terraform HCL / Plan JSON</label>
                <textarea
                  rows={3}
                  value={terraformContent}
                  onChange={(e) => setTerraformContent(e.target.value)}
                  placeholder='resource "aws_s3_bucket" "b" { acl = "public-read" }'
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs font-mono text-slate-200 mt-1"
                />
              </div>
              <div>
                <label className="text-[10px] font-mono text-slate-400 uppercase">Dockerfile</label>
                <textarea
                  rows={3}
                  value={dockerfileContent}
                  onChange={(e) => setDockerfileContent(e.target.value)}
                  placeholder={'FROM node:latest\nCMD ["node","server.js"]'}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-2.5 text-xs font-mono text-slate-200 mt-1"
                />
              </div>
            </div>
            <div className="flex justify-end space-x-2 pt-2">
              <button type="button" onClick={() => setScanTarget(null)} className="px-4 py-2 rounded-lg bg-slate-800 text-xs">
                Cancel
              </button>
              <button type="submit" className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold">
                Execute Security Scan
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Repo Settings Modal */}
      {editingProj && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <form
            onSubmit={handleSaveSettings}
            className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4 text-slate-100"
          >
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold">Project Settings — {editingProj.name}</h3>
              <button type="button" onClick={() => setEditingProj(null)} className="text-slate-400 hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>
            <div>
              <label className="text-[10px] font-mono text-slate-400 uppercase">Default Branch</label>
              <input
                type="text"
                value={editBranch}
                onChange={(e) => setEditBranch(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs mt-1"
              />
            </div>
            <div>
              <label className="text-[10px] font-mono text-slate-400 uppercase">Owner</label>
              <input
                type="text"
                value={editOwner}
                onChange={(e) => setEditOwner(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs mt-1"
              />
            </div>
            <div>
              <label className="text-[10px] font-mono text-slate-400 uppercase">SLSA Provenance Level</label>
              <select
                value={editSlsa}
                onChange={(e) => setEditSlsa(e.target.value as Project['slsaLevel'])}
                className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs mt-1"
              >
                <option value="None">None</option>
                <option value="SLSA 1">SLSA 1</option>
                <option value="SLSA 2">SLSA 2</option>
                <option value="SLSA 3">SLSA 3</option>
              </select>
            </div>
            <div className="flex justify-end space-x-2 pt-2">
              <button type="button" onClick={() => setEditingProj(null)} className="px-4 py-2 rounded-lg bg-slate-800 text-xs">
                Cancel
              </button>
              <button type="submit" className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold">
                Save Changes
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
