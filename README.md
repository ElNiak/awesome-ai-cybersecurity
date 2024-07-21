# Awesome AI in Cybersecurity Resources

[![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

Welcome to the ultimate list of resources for AI in cybersecurity. 
This repository aims to provide an organized collection of high-quality resources to help professionals, researchers, and enthusiasts stay updated and advance their knowledge in the field.

Inspired by [awesome-security](https://github.com/sbilly/awesome-security), [Awesome-AI-for-cybersecurity](https://github.com/Billy1900/Awesome-AI-for-cybersecurity) !

- [Awesome AI in Cybersecurity](#awesome-ai-in-cybersecurity)
  - [Introduction](#introduction)
  - [Using AI for Pentesting](#using-ai-for-pentesting)
    - [Tools](#tools)
    - [Frameworks](#frameworks)
    - [Tutorials and Guides](#tutorials-and-guides)
  - [Securing AI SaaS](#securing-ai-saas)
    - [Best Practices](#best-practices)
    - [Case Studies](#case-studies)
    - [Tools](#tools)
  - [Theoretical Resources](#theoretical-resources)
    - [Research Papers](#research-papers)
    - [Books](#books)
    - [Articles](#articles)
  - [Contributing](#contributing)

## Introduction

First, beginners should look at machine learning tasks and their applications. I wrote a **[machine learning blog](https://github.com/Billy1900/Awesome-Machine-Learning)** including CV (CNN, GAN), RL, GNN, NLP.

Additionally, developers still need to know more about security/cybersecurity, here is the **[awesome list of security tool and knowledge.](security.md)**

Then, let's turn to AI for cybersecurity.

The first dimension is a goal or a task. According to Gartner’s PPDR model, all security tasks can be divided into five categories:
- prediction
- prevention
- detection
- response
- monitoring

The second dimension is a technical layer and the list of layers for this dimension:
- network (network traffic analysis and intrusion detection)
- endpoint (anti-malware)
- application (WAF or database firewalls)
- user (UBA)
- process behavior (anti-fraud)

## Using AI for Pentesting

### Tools
- **Snort IDS** - [Snort IDS](https://www.snort.org/)
  - An open-source network IDS and IPS capable of real-time traffic analysis and packet logging. Snort can leverage AI for anomaly detection and to enhance its pattern matching algorithms for better intrusion detection.
- **Metasploit Framework** - [Metasploit](https://www.metasploit.com/)
  - A tool for developing and executing exploit code against a remote target machine. AI can be used to automate the selection of exploits and optimize the attack vectors based on target vulnerabilities.
- **Nmap** - [Nmap](https://nmap.org)
  - A free and open-source network scanner used to discover hosts and services on a computer network. AI can enhance Nmap's capabilities by automating the analysis of scan results and suggesting potential security weaknesses.
- **Burp Suite** - [Burp Suite](https://portswigger.net/burp)
  - A leading range of cybersecurity tools, brought to you by PortSwigger. Burp Suite can integrate AI to automate vulnerability detection and improve the efficiency of web application security testing.
- **Nikto** - [Nikto](https://github.com/sullo/nikto)
  - An open-source web server scanner which performs comprehensive tests against web servers for multiple items. AI can help Nikto by automating the identification of complex vulnerabilities and enhancing detection accuracy.
- **OpenVAS** - [OpenVAS](https://www.openvas.org/)
  - An open-source vulnerability scanner and vulnerability management solution. AI can be used to improve the identification and prioritization of vulnerabilities based on their potential impact and likelihood of exploitation.
- **OSSEC** - [OSSEC](https://www.ossec.net/)
  - An open-source host-based intrusion detection system (HIDS). AI can enhance OSSEC by providing advanced anomaly detection and predictive analysis to identify potential threats before they materialize.
- **DeepExploit** - [DeepExploit](https://github.com/13o-bbr-bbq/machine_learning_security)
  - Fully automated penetration testing framework using Machine Learning. It uses reinforcement learning to improve its attack strategies over time.

### Frameworks
- **Zeek Network Security Monitor** - [Zeek GitHub](https://github.com/zeek/zeek)
  - A powerful network analysis framework focused on security monitoring. AI can be integrated to analyze network traffic patterns and detect anomalies indicative of security threats.
- **AIEngine** - [AIEngine GitHub](https://github.com/camp0/aiengine)
  - Next-generation interactive/programmable packet inspection engine with IDS functionality. AIEngine uses machine learning to improve packet inspection and anomaly detection, adapting to new threats over time.
- **Cortex** - [Cortex](https://github.com/TheHive-Project/Cortex)
  - A powerful and flexible observable analysis and active response engine. AI can be used in Cortex to automate the analysis of observables and enhance threat detection capabilities.
- **MISP** - [MISP](https://www.misp-project.org/)
  - Open source threat intelligence platform for gathering, sharing, storing and correlating Indicators of Compromise (IoCs). AI can enhance the efficiency of threat detection and response by automating data analysis and correlation.

### Tutorials and Guides
- **Offensive AI** - [Offensive AI and Cybersecurity](https://securityintelligence.com/news/offensive-ai-and-cybersecurity-the-good-the-bad-and-the-ugly/)
  - A comprehensive guide on how AI can be used offensively in cybersecurity, discussing various scenarios and defensive measures. This guide explores the use of AI in automating attacks and evading traditional security measures.
- **AI for Ethical Hacking** - [AI in Ethical Hacking](https://resources.infosecinstitute.com/topic/ai-in-ethical-hacking/)
  - This guide covers the application of AI in ethical hacking, including how AI tools can enhance penetration testing efforts.
- **AI-Powered Penetration Testing** - [AI-Powered Penetration Testing](https://www.cybersecurity-insiders.com/ai-powered-penetration-testing/)
  - An overview of how AI can be utilized in penetration testing to improve efficiency and effectiveness.

## Securing AI SaaS

### Best Practices
- **NIST AI RMF** - [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)
  - A framework for managing risks associated with AI in SaaS. It provides guidelines on how to implement AI securely, focusing on risk assessment, mitigation, and governance.

### Case Studies
- **Microsoft AI Security** - [Microsoft AI Security](https://www.microsoft.com/en-us/security/ai)
  - Case studies on securing AI applications in SaaS environments. These case studies demonstrate how AI can be used to enhance security and protect against evolving threats.
- **Google AI Security Practices** - [Google AI Security](https://cloud.google.com/security/ai)
  - Insights and case studies from Google on how to secure AI applications in the cloud.

### Tools
- **IBM Watson for Cybersecurity** - [IBM Watson](https://www.ibm.com/security/artificial-intelligence)
  - Tools and solutions for securing AI applications. Watson uses AI to analyze vast amounts of security data and identify potential threats, providing actionable insights for cybersecurity professionals.
- **Azure Security Center** - [Azure Security Center](https://azure.microsoft.com/en-us/services/security-center/)
  - Comprehensive security management system for cloud environments. AI and machine learning are used to identify threats and vulnerabilities in real-time.

## Theoretical Resources

### Research Papers
- **AI for Cybersecurity: A Survey** - [AI Cybersecurity Survey](https://arxiv.org/abs/1901.08854)
  - A comprehensive survey of AI applications in cybersecurity. This paper reviews various AI techniques and their effectiveness in different cybersecurity domains.
- **Machine Learning Techniques for Intrusion Detection** - [Intrusion Detection](https://arxiv.org/abs/1312.2177v2)
  - A survey of machine learning techniques applied to intrusion detection.
- **A Survey of Network Anomaly Detection Techniques** - [Network Anomaly Detection](https://www.gta.ufrj.br/~alvarenga/files/CPE826/Ahmed2016-Survey.pdf)
  - A comprehensive review of network anomaly detection methods.
- **Deep Learning at the Shallow End: Malware Classification for Non-Domain Experts** - [Malware Classification](https://arxiv.org/abs/1807.08265v1)
  - A paper discussing the use of deep learning techniques for malware classification.

### Books
- **Artificial Intelligence in Cybersecurity** - [AI in Cybersecurity](https://www.springer.com/gp/book/9783030156547)
  - Detailed exploration of AI applications in cybersecurity. The book covers both theoretical foundations and practical implementations of AI in various security contexts.
- **Machine Learning and Security** - [Machine Learning and Security](https://www.oreilly.com/library/view/machine-learning-and/9781491979891/)
  - A comprehensive guide to applying machine learning techniques in cybersecurity.
- **Mastering Machine Learning for Penetration Testing** - [Mastering Machine Learning](https://www.packtpub.com/product/mastering-machine-learning-for-penetration-testing/9781788997409)
  - Practical insights into using machine learning for enhancing penetration testing efforts.
- **Malware Data Science** - [Malware Data Science](https://nostarch.com/malwaredatascience)
  - A guide to using data science techniques to understand, analyze, and detect malware.
- **AI for Cybersecurity: A Handbook of Use Cases** - [AI Handbook](https://psucybersecuritylab.github.io/)
  - A comprehensive collection of AI use cases in cybersecurity.

### Articles
- **The Role of AI in Cybersecurity** - [AI in Cybersecurity](https://www.forbes.com/sites/forbestechcouncil/2020/01/10/the-role-of-artificial-intelligence-in-cybersecurity/)
  - An article discussing various aspects of AI in cybersecurity. It highlights the benefits and challenges of using AI to enhance security measures.

## Contributing

Your contributions are always welcome! Feel free to submit a pull request with your suggestions.
