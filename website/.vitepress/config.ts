import { defineConfig } from 'vitepress'
import { withMermaid } from 'vitepress-plugin-mermaid'

// CVSS Skills 官网配置
// 部署在 GitHub Pages 项目站点根路径: https://scagogogo.github.io/cvss-skills/
// API 深度文档部署在 /docs 子路径，由 docs/.vitepress 独立构建
// withMermaid 包裹以支持 ```mermaid 代码块渲染流程图/时序图/类图等
export default withMermaid(defineConfig({
  lang: 'en-US',
  title: 'CVSS Skills',
  titleTemplate: false,
  description:
    'Professional CVSS v3.0/v3.1 toolkit — parse, score, validate, compare & build vulnerability vectors. Go SDK, CLI, Claude Code Skills, MCP.',
  base: '/cvss-skills/',
  cleanUrls: true,
  lastUpdated: true,
  ignoreDeadLinks: true,

  head: [
    ['meta', { name: 'theme-color', content: '#1677ff' }],
    [
      'meta',
      {
        name: 'keywords',
        content:
          'CVSS, CVSS 3.1, CVSS 3.0, vulnerability scoring, Go, CLI, Claude Code Skills, MCP',
      },
    ],
  ],

  locales: {
    root: {
      label: 'English',
      lang: 'en',
      themeConfig: {
        nav: nav(),
        sidebar: sidebar(),
        editLink: {
          text: 'Edit this page on GitHub',
          pattern: 'https://github.com/scagogogo/cvss-skills/edit/main/website/:path',
        },
      },
    },
    zh: {
      label: '简体中文',
      lang: 'zh-CN',
      themeConfig: {
        nav: navZh(),
        sidebar: sidebarZh(),
        editLink: {
          text: '在 GitHub 上编辑此页',
          pattern: 'https://github.com/scagogogo/cvss-skills/edit/main/website/:path',
        },
        // 本地化界面文案（VitePress 默认这些标签为英文）
        outline: { label: '本页目录' },
        docFooter: { prev: '上一页', next: '下一页' },
        lastUpdatedText: '最后更新',
        returnToTopLabel: '返回顶部',
        sidebarMenuLabel: '菜单',
        darkModeSwitchLabel: '外观',
        lightModeSwitchTitle: '切换到浅色模式',
        darkModeSwitchTitle: '切换到深色模式',
        footer: {
          message: '基于 MIT 许可证发布。',
          copyright: 'Copyright © 2024-2026 CVSS Skills',
        },
      },
    },
  },

  themeConfig: {
    logo: '/images/logo.svg',

    socialLinks: [
      { icon: 'github', link: 'https://github.com/scagogogo/cvss-skills' },
    ],

    search: { provider: 'local' },

    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © 2024-2026 CVSS Skills',
    },
  },

  // Mermaid 全局配置：固定 default 主题（暗色模式下图例仍为浅色配色）
  mermaid: {
    theme: 'default',
  },
  mermaidPlugin: {
    class: 'mermaid-diagram',
  },
}))

function nav() {
  return [
    { text: 'Guide', link: '/', activeMatch: '^/$' },
    { text: 'CLI', link: '/cli/', activeMatch: '^/cli/' },
    { text: 'Go SDK', link: '/sdk/', activeMatch: '^/sdk/' },
    { text: 'Metrics', link: '/metrics/', activeMatch: '^/metrics/' },
    { text: 'Concepts', link: '/concepts/', activeMatch: '^/concepts/' },
    { text: 'Tutorials', link: '/tutorials/', activeMatch: '^/tutorials/' },
    { text: 'Recipes', link: '/recipes/', activeMatch: '^/recipes/' },
    { text: 'Downloads', link: '/downloads/' },
    { text: 'API Reference', link: '/docs/api/' },
    { text: 'GitHub', link: 'https://github.com/scagogogo/cvss-skills' },
  ]
}

function navZh() {
  return [
    { text: '指南', link: '/zh/', activeMatch: '^/zh/$' },
    { text: '命令行', link: '/zh/cli/', activeMatch: '^/zh/cli/' },
    { text: 'Go SDK', link: '/zh/sdk/', activeMatch: '^/zh/sdk/' },
    { text: '指标', link: '/zh/metrics/', activeMatch: '^/zh/metrics/' },
    { text: '概念', link: '/zh/concepts/', activeMatch: '^/zh/concepts/' },
    { text: '教程', link: '/zh/tutorials/', activeMatch: '^/zh/tutorials/' },
    { text: '菜谱', link: '/zh/recipes/', activeMatch: '^/zh/recipes/' },
    { text: '下载', link: '/zh/downloads/' },
    { text: 'API 参考', link: '/docs/zh/api/' },
    { text: 'GitHub', link: 'https://github.com/scagogogo/cvss-skills' },
  ]
}

// ---- CLI 命令分组（与 sidebar 共用，保证中英一致） ----
function cliGroups() {
  return [
    {
      text: 'Score & Rate',
      items: [
        { text: 'score', link: '/cli/commands/score' },
        { text: 'severity', link: '/cli/commands/severity' },
        { text: 'describe', link: '/cli/commands/describe' },
        { text: 'subs', link: '/cli/commands/subs' },
        { text: 'analyze', link: '/cli/commands/analyze' },
      ],
    },
    {
      text: 'Parse & Build',
      items: [
        { text: 'parse', link: '/cli/commands/parse' },
        { text: 'build', link: '/cli/commands/build' },
        { text: 'validate', link: '/cli/commands/validate' },
        { text: 'canonicalize', link: '/cli/commands/canonicalize' },
        { text: 'modify', link: '/cli/commands/modify' },
        { text: 'merge', link: '/cli/commands/merge' },
        { text: 'strip / base-only', link: '/cli/commands/strip' },
        { text: 'convert', link: '/cli/commands/convert' },
      ],
    },
    {
      text: 'Inspect & Serialize',
      items: [
        { text: 'get', link: '/cli/commands/get' },
        { text: 'groups', link: '/cli/commands/groups' },
        { text: 'map', link: '/cli/commands/map' },
        { text: 'json', link: '/cli/commands/json' },
        { text: 'enumerate', link: '/cli/commands/enumerate' },
      ],
    },
    {
      text: 'Compare & Measure',
      items: [
        { text: 'diff', link: '/cli/commands/diff' },
        { text: 'equal', link: '/cli/commands/equal' },
        { text: 'distance', link: '/cli/commands/distance' },
      ],
    },
    {
      text: 'Batch & Files',
      items: [
        { text: 'batch score', link: '/cli/commands/batch-score' },
        { text: 'batch validate', link: '/cli/commands/batch-validate' },
        { text: 'sort', link: '/cli/commands/sort' },
        { text: 'csv write', link: '/cli/commands/csv-write' },
        { text: 'csv read', link: '/cli/commands/csv-read' },
      ],
    },
    {
      text: 'Generate',
      items: [
        { text: 'preset', link: '/cli/commands/preset' },
        { text: 'random', link: '/cli/commands/random' },
        { text: 'range', link: '/cli/commands/range' },
        { text: 'completion', link: '/cli/commands/completion' },
      ],
    },
  ]
}

function cliGroupsZh() {
  return [
    {
      text: '评分与定级',
      items: [
        { text: 'score', link: '/zh/cli/commands/score' },
        { text: 'severity', link: '/zh/cli/commands/severity' },
        { text: 'describe', link: '/zh/cli/commands/describe' },
        { text: 'subs', link: '/zh/cli/commands/subs' },
        { text: 'analyze', link: '/zh/cli/commands/analyze' },
      ],
    },
    {
      text: '解析与构建',
      items: [
        { text: 'parse', link: '/zh/cli/commands/parse' },
        { text: 'build', link: '/zh/cli/commands/build' },
        { text: 'validate', link: '/zh/cli/commands/validate' },
        { text: 'canonicalize', link: '/zh/cli/commands/canonicalize' },
        { text: 'modify', link: '/zh/cli/commands/modify' },
        { text: 'merge', link: '/zh/cli/commands/merge' },
        { text: 'strip / base-only', link: '/zh/cli/commands/strip' },
        { text: 'convert', link: '/zh/cli/commands/convert' },
      ],
    },
    {
      text: '查看与序列化',
      items: [
        { text: 'get', link: '/zh/cli/commands/get' },
        { text: 'groups', link: '/zh/cli/commands/groups' },
        { text: 'map', link: '/zh/cli/commands/map' },
        { text: 'json', link: '/zh/cli/commands/json' },
        { text: 'enumerate', link: '/zh/cli/commands/enumerate' },
      ],
    },
    {
      text: '比较与度量',
      items: [
        { text: 'diff', link: '/zh/cli/commands/diff' },
        { text: 'equal', link: '/zh/cli/commands/equal' },
        { text: 'distance', link: '/zh/cli/commands/distance' },
      ],
    },
    {
      text: '批量与文件',
      items: [
        { text: 'batch score', link: '/zh/cli/commands/batch-score' },
        { text: 'batch validate', link: '/zh/cli/commands/batch-validate' },
        { text: 'sort', link: '/zh/cli/commands/sort' },
        { text: 'csv write', link: '/zh/cli/commands/csv-write' },
        { text: 'csv read', link: '/zh/cli/commands/csv-read' },
      ],
    },
    {
      text: '生成',
      items: [
        { text: 'preset', link: '/zh/cli/commands/preset' },
        { text: 'random', link: '/zh/cli/commands/random' },
        { text: 'range', link: '/zh/cli/commands/range' },
        { text: 'completion', link: '/zh/cli/commands/completion' },
      ],
    },
  ]
}

// ---- Go SDK 分组（与 sidebar 共用） ----
function sdkGroups() {
  return [
    { text: 'Overview', link: '/sdk/' },
    { text: 'pkg/cvss', link: '/sdk/cvss' },
    { text: 'pkg/parser', link: '/sdk/parser' },
    { text: 'pkg/vector', link: '/sdk/vector' },
    { text: 'pkg/mock', link: '/sdk/mock' },
    { text: 'Cvss3x type', link: '/sdk/cvss3x' },
    { text: 'Base / Temporal / Env', link: '/sdk/cvss3x-base' },
    { text: 'Errors', link: '/sdk/errors' },
    { text: 'Scoring (calculator)', link: '/sdk/calculator' },
    { text: 'Scores & sub-scores', link: '/sdk/scores' },
    { text: 'Severity', link: '/sdk/severity' },
    { text: 'Score breakdown', link: '/sdk/breakdown' },
    { text: 'Score range', link: '/sdk/score-range' },
    { text: 'Builder Pattern', link: '/sdk/builder' },
    { text: 'Functional Options', link: '/sdk/options' },
    { text: 'With-Method setters', link: '/sdk/with-method' },
    { text: 'From Map / Values', link: '/sdk/from-map' },
    { text: 'Accessor', link: '/sdk/accessor' },
    { text: 'Presets', link: '/sdk/presets' },
    { text: 'Convenience', link: '/sdk/convenience' },
    { text: 'Conversion', link: '/sdk/conversion' },
    { text: 'Diff & Merge', link: '/sdk/diff' },
    { text: 'Distance', link: '/sdk/distance' },
    { text: 'Impact & Sensitivity', link: '/sdk/impact' },
    { text: 'Validation', link: '/sdk/validation' },
    { text: 'Enumeration', link: '/sdk/enumerate' },
    { text: 'JSON Serialization', link: '/sdk/json' },
    { text: 'CSV I/O', link: '/sdk/csv' },
    { text: 'Batch', link: '/sdk/batch' },
    { text: 'SQL & Sorting', link: '/sdk/sql-sort' },
    { text: 'Vector interface', link: '/sdk/vector-interface' },
    { text: 'Vector factory', link: '/sdk/vector-factory' },
    { text: 'Not-Defined vectors', link: '/sdk/vector-not-defined' },
  ]
}

function sdkGroupsZh() {
  return [
    { text: '总览', link: '/zh/sdk/' },
    { text: 'pkg/cvss', link: '/zh/sdk/cvss' },
    { text: 'pkg/parser', link: '/zh/sdk/parser' },
    { text: 'pkg/vector', link: '/zh/sdk/vector' },
    { text: 'pkg/mock', link: '/zh/sdk/mock' },
    { text: 'Cvss3x 类型', link: '/zh/sdk/cvss3x' },
    { text: 'Base/Temporal/Env', link: '/zh/sdk/cvss3x-base' },
    { text: '错误', link: '/zh/sdk/errors' },
    { text: '评分计算器', link: '/zh/sdk/calculator' },
    { text: '评分与子分数', link: '/zh/sdk/scores' },
    { text: '严重性', link: '/zh/sdk/severity' },
    { text: '分数分解', link: '/zh/sdk/breakdown' },
    { text: '评分范围', link: '/zh/sdk/score-range' },
    { text: 'Builder 构建器', link: '/zh/sdk/builder' },
    { text: 'Functional Options', link: '/zh/sdk/options' },
    { text: 'With-Method setter', link: '/zh/sdk/with-method' },
    { text: 'Map 与值构造', link: '/zh/sdk/from-map' },
    { text: '指标读写器', link: '/zh/sdk/accessor' },
    { text: '预设向量', link: '/zh/sdk/presets' },
    { text: '便捷方法', link: '/zh/sdk/convenience' },
    { text: '版本转换', link: '/zh/sdk/conversion' },
    { text: '差异与合并', link: '/zh/sdk/diff' },
    { text: '距离', link: '/zh/sdk/distance' },
    { text: '影响与敏感性', link: '/zh/sdk/impact' },
    { text: '校验', link: '/zh/sdk/validation' },
    { text: '枚举', link: '/zh/sdk/enumerate' },
    { text: 'JSON 序列化', link: '/zh/sdk/json' },
    { text: 'CSV 读写', link: '/zh/sdk/csv' },
    { text: '批量', link: '/zh/sdk/batch' },
    { text: 'SQL 与排序', link: '/zh/sdk/sql-sort' },
    { text: 'Vector 接口', link: '/zh/sdk/vector-interface' },
    { text: 'Vector 工厂', link: '/zh/sdk/vector-factory' },
    { text: 'Not-Defined 向量', link: '/zh/sdk/vector-not-defined' },
  ]
}

function sidebar() {
  return [
    {
      text: 'Guide',
      items: [
        { text: 'Introduction', link: '/' },
        { text: 'Integration Methods', link: '/integration/' },
        { text: 'CLI Reference', link: '/cli/' },
        { text: 'Downloads', link: '/downloads/' },
      ],
    },
    {
      text: 'CLI Commands',
      collapsed: false,
      items: [
        { text: 'Overview', link: '/cli/' },
        ...cliGroups().flatMap((g) => g.items),
      ],
    },
    {
      text: 'Go SDK',
      collapsed: false,
      items: sdkGroups(),
    },
    {
      text: 'CVSS Metrics',
      collapsed: true,
      items: [
        { text: 'Overview', link: '/metrics/' },
        { text: 'Attack Vector (AV)', link: '/metrics/attack-vector' },
        { text: 'Attack Complexity (AC)', link: '/metrics/attack-complexity' },
        { text: 'Privileges Required (PR)', link: '/metrics/privileges-required' },
        { text: 'User Interaction (UI)', link: '/metrics/user-interaction' },
        { text: 'Scope (S)', link: '/metrics/scope' },
        { text: 'Confidentiality (C)', link: '/metrics/confidentiality' },
        { text: 'Integrity (I)', link: '/metrics/integrity' },
        { text: 'Availability (A)', link: '/metrics/availability' },
        { text: 'Exploit Code Maturity (E)', link: '/metrics/exploit-code-maturity' },
        { text: 'Remediation Level (RL)', link: '/metrics/remediation-level' },
        { text: 'Report Confidence (RC)', link: '/metrics/report-confidence' },
        { text: 'Requirements (CR/IR/AR)', link: '/metrics/requirements' },
        { text: 'Modified Metrics (M*)', link: '/metrics/modified' },
      ],
    },
    {
      text: 'Concepts',
      collapsed: true,
      items: [
        { text: 'Overview', link: '/concepts/' },
        { text: 'Severity Ratings', link: '/concepts/severity' },
        { text: 'Scoring Formulas', link: '/concepts/scoring-formula' },
        { text: 'v3.0 vs v3.1', link: '/concepts/version-diff' },
        { text: 'Validation Model', link: '/concepts/validation' },
        { text: 'Distance Metrics', link: '/concepts/distance' },
        { text: 'Presets & Severity', link: '/concepts/presets' },
      ],
    },
    {
      text: 'Tutorials',
      collapsed: false,
      items: [
        { text: 'Overview', link: '/tutorials/' },
        { text: 'Getting Started', link: '/tutorials/getting-started' },
        { text: 'Your First Vector', link: '/tutorials/your-first-vector' },
        { text: 'Scoring Walkthrough', link: '/tutorials/scoring-walkthrough' },
        { text: 'Validation Workflow', link: '/tutorials/validation-workflow' },
        { text: 'Comparison Guide', link: '/tutorials/comparison-guide' },
        { text: 'Batch Scripting', link: '/tutorials/batch-scripting' },
        { text: 'Building Vectors', link: '/tutorials/building-vectors' },
        { text: 'Version Migration', link: '/tutorials/version-migration' },
        { text: 'Presets and Random', link: '/tutorials/presets-and-random' },
      ],
    },
    {
      text: 'Recipes',
      collapsed: true,
      items: [
        { text: 'Overview', link: '/recipes/' },
        { text: 'Filter Critical Vulns', link: '/recipes/filter-critical-vulns' },
        { text: 'Sort by Severity', link: '/recipes/sort-by-severity' },
        { text: 'Parse from CSV', link: '/recipes/parse-from-csv' },
        { text: 'Export to JSON', link: '/recipes/export-to-json' },
        { text: 'Compare Two Vectors', link: '/recipes/compare-two-vectors' },
        { text: 'Measure Similarity', link: '/recipes/measure-similarity' },
        { text: 'Build from Scan', link: '/recipes/build-from-scan' },
        { text: 'Migrate v3.0 → v3.1', link: '/recipes/migrate-v3-to-v31' },
        { text: 'Score Partial Vector', link: '/recipes/score-partial-vector' },
        { text: 'Generate Test Data', link: '/recipes/generate-test-data' },
        { text: 'Store in Database', link: '/recipes/store-in-database' },
      ],
    },
  ]
}

function sidebarZh() {
  return [
    {
      text: '指南',
      items: [
        { text: '简介', link: '/zh/' },
        { text: '集成方式', link: '/zh/integration/' },
        { text: '命令行参考', link: '/zh/cli/' },
        { text: '下载', link: '/zh/downloads/' },
      ],
    },
    {
      text: 'CLI 命令',
      collapsed: false,
      items: [
        { text: '总览', link: '/zh/cli/' },
        ...cliGroupsZh().flatMap((g) => g.items),
      ],
    },
    {
      text: 'Go SDK',
      collapsed: false,
      items: sdkGroupsZh(),
    },
    {
      text: 'CVSS 指标',
      collapsed: true,
      items: [
        { text: '总览', link: '/zh/metrics/' },
        { text: '攻击向量 (AV)', link: '/zh/metrics/attack-vector' },
        { text: '攻击复杂度 (AC)', link: '/zh/metrics/attack-complexity' },
        { text: '所需权限 (PR)', link: '/zh/metrics/privileges-required' },
        { text: '用户交互 (UI)', link: '/zh/metrics/user-interaction' },
        { text: '范围 (S)', link: '/zh/metrics/scope' },
        { text: '机密性 (C)', link: '/zh/metrics/confidentiality' },
        { text: '完整性 (I)', link: '/zh/metrics/integrity' },
        { text: '可用性 (A)', link: '/zh/metrics/availability' },
        { text: '利用代码成熟度 (E)', link: '/zh/metrics/exploit-code-maturity' },
        { text: '修复级别 (RL)', link: '/zh/metrics/remediation-level' },
        { text: '报告可信度 (RC)', link: '/zh/metrics/report-confidence' },
        { text: '安全需求 (CR/IR/AR)', link: '/zh/metrics/requirements' },
        { text: '修改后指标 (M*)', link: '/zh/metrics/modified' },
      ],
    },
    {
      text: '概念',
      collapsed: true,
      items: [
        { text: '总览', link: '/zh/concepts/' },
        { text: '严重性等级', link: '/zh/concepts/severity' },
        { text: '评分公式', link: '/zh/concepts/scoring-formula' },
        { text: 'v3.0 与 v3.1 差异', link: '/zh/concepts/version-diff' },
        { text: '校验模型', link: '/zh/concepts/validation' },
        { text: '距离度量', link: '/zh/concepts/distance' },
        { text: '预设与严重性', link: '/zh/concepts/presets' },
      ],
    },
    {
      text: '教程',
      collapsed: false,
      items: [
        { text: '总览', link: '/zh/tutorials/' },
        { text: '快速入门', link: '/zh/tutorials/getting-started' },
        { text: '你的第一个向量', link: '/zh/tutorials/your-first-vector' },
        { text: '评分实战', link: '/zh/tutorials/scoring-walkthrough' },
        { text: '校验工作流', link: '/zh/tutorials/validation-workflow' },
        { text: '比较指南', link: '/zh/tutorials/comparison-guide' },
        { text: '批处理脚本', link: '/zh/tutorials/batch-scripting' },
        { text: '构建向量', link: '/zh/tutorials/building-vectors' },
        { text: '版本迁移', link: '/zh/tutorials/version-migration' },
        { text: '预设与随机', link: '/zh/tutorials/presets-and-random' },
      ],
    },
    {
      text: '菜谱',
      collapsed: true,
      items: [
        { text: '总览', link: '/zh/recipes/' },
        { text: '筛选严重漏洞', link: '/zh/recipes/filter-critical-vulns' },
        { text: '按严重性排序', link: '/zh/recipes/sort-by-severity' },
        { text: '从 CSV 解析', link: '/zh/recipes/parse-from-csv' },
        { text: '导出 JSON', link: '/zh/recipes/export-to-json' },
        { text: '比较两个向量', link: '/zh/recipes/compare-two-vectors' },
        { text: '度量相似度', link: '/zh/recipes/measure-similarity' },
        { text: '从扫描结果构建', link: '/zh/recipes/build-from-scan' },
        { text: 'v3.0 迁移到 v3.1', link: '/zh/recipes/migrate-v3-to-v31' },
        { text: '部分向量评分', link: '/zh/recipes/score-partial-vector' },
        { text: '生成测试数据', link: '/zh/recipes/generate-test-data' },
        { text: '存入数据库', link: '/zh/recipes/store-in-database' },
      ],
    },
  ]
}
