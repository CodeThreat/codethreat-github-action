const { describe, test, expect, beforeEach, afterEach } = require('@jest/globals');
const axios = require('axios');
const fs = require('fs').promises;

jest.mock('@actions/core', () => ({
  getInput: jest.fn().mockReturnValue('{}'),
  setFailed: jest.fn(),
  warning: jest.fn(),
  info: jest.fn(),
  setOutput: jest.fn()
}));

jest.mock('@actions/github', () => ({
  context: {
    repo: {
      owner: 'test-owner',
      repo: 'test-repo'
    },
    ref: 'refs/heads/main',
    payload: {
      repository: {
        private: false,
        id: '12345'
      },
      after: 'test-commit-sha',
      head_commit: {
        message: 'test commit message'
      }
    },
    actor: 'test-user',
    eventName: 'push'
  }
}));

jest.mock('@octokit/rest', () => ({
  Octokit: jest.fn().mockImplementation(() => ({
    repos: {
      createCommitComment: jest.fn().mockResolvedValue({}),
    },
    pulls: {
      createReview: jest.fn().mockResolvedValue({}),
      update: jest.fn().mockResolvedValue({}),
      merge: jest.fn().mockResolvedValue({})
    }
  }))
}));

jest.mock('../utils', () => ({
  getOrg: jest.fn(),
  login: jest.fn(),
  check: jest.fn(),
  create: jest.fn(),
  start: jest.fn(),
  status: jest.fn(),
  result: jest.fn(),
  saveSarif: jest.fn(),
  findWeaknessTitles: jest.fn(),
  failedArgs: jest.fn().mockReturnValue({
    max_number_of_critical: 0,
    max_number_of_high: 2,
    weakness_is: '',
    condition: 'AND',
    sync_scan: true,
    policy_name: 'Test Policy',
    automerge: false
  }),
  getEnvVars: jest.fn().mockReturnValue({
    token: 'mock-token',
    ctServer: 'https://example.com',
    username: 'test-user',
    password: 'test-pass',
    orgname: 'test-org',
    githubtoken: 'mock-github-token'
  })
}));

global.console.log = jest.fn();

describe('CodeThreat GitHub Action', () => {
  let utils;
  let index;
  
  beforeEach(() => {
    jest.resetModules();
    jest.clearAllMocks();
    
    utils = require('../utils');
    index = require('../index');
    
    utils.getEnvVars.mockReturnValue({
      token: 'mock-token',
      ctServer: 'https://example.com',
      username: undefined,
      password: undefined,
      orgname: 'test-org',
      githubtoken: 'mock-github-token'
    });
    
    utils.getOrg.mockResolvedValue({ success: true });
    utils.login.mockResolvedValue('mock-token');
    utils.check.mockResolvedValue({ type: 'project' });
    utils.create.mockResolvedValue({ success: true });
    utils.start.mockResolvedValue({ data: { scan_id: 'test-scan-id' } });
    utils.status.mockResolvedValue({
      state: 'end',
      progress: 100,
      severities: { critical: 0, high: 0 },
      weaknessesArr: []
    });
    utils.result.mockResolvedValue({
      type: 'success',
      report: 'Test Report',
      scaSeverityCounts: {
        Critical: 0,
        High: 0
      }
    });
    utils.saveSarif.mockResolvedValue({ success: true });
    utils.findWeaknessTitles.mockResolvedValue([]);
  });

  describe('Authentication', () => {
    test('should authenticate successfully with token', async () => {
      await index.loginIn();
      expect(utils.getOrg).toHaveBeenCalledWith(
        'https://example.com',
        'mock-token',
        'test-org'
      );
    });

    test('should authenticate successfully with username/password', async () => {
      utils.getEnvVars.mockReturnValueOnce({
        token: undefined,
        ctServer: 'https://example.com',
        username: 'test-user',
        password: 'test-pass',
        orgname: 'test-org'
      });
      
      await index.loginIn();
      expect(utils.login).toHaveBeenCalledWith(
        'https://example.com',
        'test-user',
        'test-pass'
      );
    });

    test('should throw error when no credentials provided', async () => {
      utils.getEnvVars.mockReturnValueOnce({
        token: undefined,
        ctServer: 'https://example.com',
        username: undefined,
        password: undefined,
        orgname: 'test-org'
      });
      
      await expect(index.loginIn()).rejects.toThrow('Please enter username and password or token.');
    });
  });

  describe('Project Operations', () => {
    test('should check and create project if needed', async () => {
      utils.check.mockResolvedValueOnce({ type: null });
      await index.loginIn();
      await index.checkProject();
      
      expect(utils.check).toHaveBeenCalled();
      await index.createProject();
      expect(utils.create).toHaveBeenCalled();
    });

    test('should not create project if it exists', async () => {
      utils.check.mockResolvedValueOnce({ type: 'project' });
      await index.loginIn();
      await index.checkProject();
      
      expect(utils.check).toHaveBeenCalled();
      expect(utils.create).not.toHaveBeenCalled();
    });
  });

  describe('Scan Operations', () => {
    test('should start scan and monitor status', async () => {
      await index.loginIn();
      const result = await index.startScan();

      expect(utils.start).toHaveBeenCalled();
      expect(utils.status).toHaveBeenCalledWith(
        'https://example.com',
        'test-scan-id',
        expect.any(String),
        'test-org'
      );
      expect(result).toEqual({ data: { scan_id: 'test-scan-id' } });
    });

    test('should handle scan completion', async () => {
      utils.status.mockResolvedValueOnce({
        state: 'end',
        progress: 100,
        severities: { critical: 0, high: 0 },
        weaknessesArr: []
      });

      await index.loginIn();
      await index.startScan();

      expect(utils.result).toHaveBeenCalled();
      expect(utils.saveSarif).toHaveBeenCalled();
    });
  });

  describe('Error Handling', () => {
    test('should handle scan failure', async () => {
      utils.status.mockResolvedValueOnce({
        state: 'failure'
      });

      await index.loginIn();
      await expect(index.startScan()).rejects.toThrow('Scan Failed.');
    });

    test('should handle network errors gracefully', async () => {
      utils.getOrg.mockRejectedValueOnce(new Error('Network Error'));
      await expect(index.loginIn()).rejects.toThrow('Network Error');
    });
  });
}); 