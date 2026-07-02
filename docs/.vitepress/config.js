import { defineConfig } from 'vitepress'
import { withMermaid } from 'vitepress-plugin-mermaid'

// withMermaid 包裹以支持 ```mermaid 代码块渲染类图/时序图/流程图等
export default withMermaid(defineConfig({
  title: 'CVSS Skills',
  description: 'Go CVSS Parsing & Scoring Library - Complete API Documentation',
  base: '/cvss-skills/docs/',
  ignoreDeadLinks: true,

  // 国际化配置
  locales: {
    root: {
      label: 'English',
      lang: 'en',
      title: 'CVSS Skills',
      description: 'Go CVSS Parsing & Scoring Library - Complete API Documentation',
      themeConfig: {
        nav: [
          { text: 'Home', link: '/' },
          { text: 'API Docs', link: '/api/' },
          { text: 'Examples', link: '/examples/' },
          { text: 'GitHub', link: 'https://github.com/scagogogo/cvss-skills' }
        ],
        sidebar: {
          '/api/': [
            {
              text: 'API Reference',
              items: [
                { text: 'Overview', link: '/api/' },
                { text: 'Getting Started', link: '/api/getting-started' },
                {
                  text: 'Core Packages',
                  collapsed: false,
                  items: [
                    { text: 'cvss', link: '/api/cvss/' },
                    { text: 'parser', link: '/api/parser/' },
                    { text: 'vector', link: '/api/vector/' }
                  ]
                },
                {
                  text: 'CVSS Package Details',
                  collapsed: true,
                  items: [
                    { text: 'Cvss3x', link: '/api/cvss/cvss3x' },
                    { text: 'Calculator', link: '/api/cvss/calculator' },
                    { text: 'Distance Calculator', link: '/api/cvss/distance' },
                    { text: 'JSON Support', link: '/api/cvss/json' },
                    { text: 'Comparison', link: '/api/cvss/comparison' }
                  ]
                },
                {
                  text: 'Parser Package Details',
                  collapsed: true,
                  items: [
                    { text: 'Cvss3xParser', link: '/api/parser/cvss3x-parser' }
                  ]
                },
                {
                  text: 'Vector Package Details',
                  collapsed: true,
                  items: [
                    { text: 'Vector Interface', link: '/api/vector/interface' }
                  ]
                },
                {
                  text: 'Guides',
                  collapsed: true,
                  items: [
                    { text: 'Error Handling', link: '/api/error-handling' },
                    { text: 'Performance', link: '/api/performance' },
                    { text: 'Testing', link: '/api/testing' }
                  ]
                }
              ]
            }
          ],
          '/examples/': [
            {
              text: 'Examples',
              items: [
                { text: 'Overview', link: '/examples/' },
                { text: 'Basic Usage', link: '/examples/basic' },
                { text: 'Parsing Vectors', link: '/examples/parsing' },
                { text: 'JSON Output', link: '/examples/json' },
                { text: 'Temporal Metrics', link: '/examples/temporal' },
                { text: 'Environmental Metrics', link: '/examples/environmental' },
                { text: 'Distance Calculation', link: '/examples/distance' },
                { text: 'Vector Comparison', link: '/examples/comparison' },
                { text: 'Severity Levels', link: '/examples/severity' },
                { text: 'Edge Cases', link: '/examples/edge-cases' },
                { text: 'Performance', link: '/examples/performance' },
                { text: 'Monitoring', link: '/examples/monitoring' },
                { text: 'Security', link: '/examples/security' },
                { text: 'Risk Assessment', link: '/examples/risk-assessment' },
                { text: 'Production', link: '/examples/production' }
              ]
            }
          ]
        }
      }
    },
    zh: {
      label: '简体中文',
      lang: 'zh-CN',
      title: 'CVSS Skills',
      description: 'Go语言CVSS解析与评分库 - 完整的API文档',
      themeConfig: {
        nav: [
          { text: '首页', link: '/zh/' },
          { text: 'API文档', link: '/zh/api/' },
          { text: '示例', link: '/zh/examples/' },
          { text: 'GitHub', link: 'https://github.com/scagogogo/cvss-skills' }
        ],
        sidebar: {
          '/zh/api/': [
            {
              text: 'API 参考',
              items: [
                { text: '概述', link: '/zh/api/' },
                { text: '快速开始', link: '/zh/api/getting-started' },
                {
                  text: '核心包',
                  collapsed: false,
                  items: [
                    { text: 'cvss', link: '/zh/api/cvss/' },
                    { text: 'parser', link: '/zh/api/parser/' },
                    { text: 'vector', link: '/zh/api/vector/' }
                  ]
                },
                {
                  text: 'CVSS 包详细文档',
                  collapsed: true,
                  items: [
                    { text: 'Cvss3x', link: '/zh/api/cvss/cvss3x' },
                    { text: '计算器', link: '/zh/api/cvss/calculator' },
                    { text: '距离计算器', link: '/zh/api/cvss/distance' },
                    { text: '向量比较', link: '/zh/api/cvss/comparison' },
                    { text: 'JSON 支持', link: '/zh/api/cvss/json' }
                  ]
                },
                {
                  text: '解析器包',
                  collapsed: true,
                  items: [
                    { text: 'Cvss3x解析器', link: '/zh/api/parser/cvss3x-parser' }
                  ]
                },
                {
                  text: '向量包',
                  collapsed: true,
                  items: [
                    { text: '向量接口', link: '/zh/api/vector/interface' }
                  ]
                },
                {
                  text: '指南',
                  collapsed: true,
                  items: [
                    { text: '错误处理', link: '/zh/api/error-handling' }
                  ]
                }
              ]
            }
          ],
          '/zh/examples/': [
            {
              text: '示例',
              items: [
                { text: '概述', link: '/zh/examples/' },
                { text: '基础用法', link: '/zh/examples/basic' },
                { text: '解析向量', link: '/zh/examples/parsing' },
                { text: 'JSON 输出', link: '/zh/examples/json' },
                { text: '时间指标', link: '/zh/examples/temporal' },
                { text: '环境指标', link: '/zh/examples/environmental' },
                { text: '距离计算', link: '/zh/examples/distance' },
                { text: '向量比较', link: '/zh/examples/comparison' },
                { text: '严重性级别', link: '/zh/examples/severity' },
                { text: '边缘情况', link: '/zh/examples/edge-cases' },
                { text: '性能优化', link: '/zh/examples/performance' },
                { text: '监控集成', link: '/zh/examples/monitoring' },
                { text: '安全评估', link: '/zh/examples/security' },
                { text: '风险评估', link: '/zh/examples/risk-assessment' },
                { text: '生产环境', link: '/zh/examples/production' }
              ]
            }
          ]
        }
      }
    }
  },

  // 全局配置
  themeConfig: {
    // 语言切换
    localeLinks: {
      text: 'Languages',
      items: [
        { text: 'English', link: '/' },
        { text: '简体中文', link: '/zh/' }
      ]
    },
    nav: [
      { text: 'Home', link: '/' },
      { text: 'API Docs', link: '/api/' },
      { text: 'Examples', link: '/examples/' },
      { text: 'GitHub', link: 'https://github.com/scagogogo/cvss-skills' }
    ],

    sidebar: {
      '/api/': [
        {
          text: 'API Reference',
          items: [
            { text: 'Overview', link: '/api/' },
            { text: 'Getting Started', link: '/api/getting-started' },
            {
              text: 'Core Packages',
              collapsed: false,
              items: [
                { text: 'cvss', link: '/api/cvss/' },
                { text: 'parser', link: '/api/parser/' },
                { text: 'vector', link: '/api/vector/' }
              ]
            },
            {
              text: 'CVSS Package Details',
              collapsed: true,
              items: [
                { text: 'Cvss3x', link: '/api/cvss/cvss3x' },
                { text: 'Calculator', link: '/api/cvss/calculator' },
                { text: 'Distance Calculator', link: '/api/cvss/distance' },
                { text: 'JSON Support', link: '/api/cvss/json' },
                { text: 'Comparison', link: '/api/cvss/comparison' }
              ]
            },
            {
              text: 'Parser Package Details',
              collapsed: true,
              items: [
                { text: 'Cvss3xParser', link: '/api/parser/cvss3x-parser' }
              ]
            },
            {
              text: 'Vector Package Details',
              collapsed: true,
              items: [
                { text: 'Vector Interface', link: '/api/vector/interface' }
              ]
            },
            {
              text: 'Guides',
              collapsed: true,
              items: [
                { text: 'Error Handling', link: '/api/error-handling' },
                { text: 'Performance', link: '/api/performance' },
                { text: 'Testing', link: '/api/testing' }
              ]
            }
          ]
        }
      ],
      '/examples/': [
        {
          text: 'Examples',
          items: [
            { text: 'Overview', link: '/examples/' },
            { text: 'Basic Usage', link: '/examples/basic' },
            { text: 'Parsing Vectors', link: '/examples/parsing' },
            { text: 'JSON Output', link: '/examples/json' },
            { text: 'Temporal Metrics', link: '/examples/temporal' },
            { text: 'Environmental Metrics', link: '/examples/environmental' },
            { text: 'Distance Calculation', link: '/examples/distance' },
            { text: 'Vector Comparison', link: '/examples/comparison' },
            { text: 'Severity Levels', link: '/examples/severity' },
            { text: 'Edge Cases', link: '/examples/edge-cases' },
            { text: 'Performance', link: '/examples/performance' },
            { text: 'Monitoring', link: '/examples/monitoring' },
            { text: 'Security', link: '/examples/security' },
            { text: 'Risk Assessment', link: '/examples/risk-assessment' },
            { text: 'Production', link: '/examples/production' }
          ]
        }
      ]
    },

    socialLinks: [
      { icon: 'github', link: 'https://github.com/scagogogo/cvss-skills' }
    ],

    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © 2024-2026 CVSS Skills'
    },

    search: {
      provider: 'local'
    }
  },

  // Mermaid 全局配置
  mermaid: {
    theme: 'default'
  },
  mermaidPlugin: {
    class: 'mermaid-diagram'
  }
}))
