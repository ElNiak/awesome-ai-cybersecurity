# Awesome AI in Cybersecurity Resou
[![Awesome](https://awesome.re/badge-flat2.svg)](https://awesome.re)

Welcome to the ultimate list of resources for AI in cybersecurity. 
This repository aims to provide an organized collection of high-quality resources to help professionals, researchers, and enthusiasts stay updated and advance their knowledge in the field.

## Contents

- [Introduction](#introduction)
- [Using AI for Pentesting](#using-ai-for-pentesting)
- [Securing AI SaaS](#securing-ai-saas)
- [Theoretical Resources](#theoretical-resources)

## Introduction

AI applications in cybersecurity can be categorized using Gartner's PPDR model:
- Prediction
- Prevention
- Detection
- Response
- Monitoring

Additionally, AI applications can be divided by technical layers:
- Network (network traffic analysis and intrusion detection)
- Endpoint (anti-malware)
- Application (WAF or database firewalls)
- User (UBA)
- Process behavior (anti-fraud)

## Using AI for Pentesting

### Prediction
#### Network
- [DeepExploit](https://github.com/13o-bbr-bbq/machine_learning_security) - Fully automated penetration testing framework using Machine Learning. It uses reinforcement learning to improve its attack strategies over time.
- [open-appsec](https://github.com/openappsec/openappsec) - open-appsec is an open source machine-learning security engine that preemptively and automatically prevents threats against Web Application & APIs.

#### Malware
- [OpenVAS](https://www.openvas.org/) - An open-source vulnerability scanner and vulnerability management solution. AI can be used to improve the identification and prioritization of vulnerabilities based on their potential impact and likelihood of exploitation.
- [SEMA](https://github.com/csvl/SEMA-ToolChain) - ToolChain using Symbolic Execution for Malware Analysis. SEMA provides a framework for symbolic execution to extract execution traces and build system call dependency graphs (SCDGs). These graphs are used for malware classification and analysis, enabling the detection of malware based on symbolic execution and machine learning techniques.
- [Malware environment for OpenAI Gym](https://github.com/endgameinc/gym-malware) - Create an AI that learns through reinforcement learning which functionality-preserving transformations to make on a malware sample to break through / bypass machine learning static-analysis malware detection.
  
### Prevention
#### Network
- [Snort IDS](https://www.snort.org/) - An open-source network IDS and IPS capable of real-time traffic analysis and packet logging. Snort can leverage AI for anomaly detection and to enhance its pattern matching algorithms for better intrusion detection.
- [PANTHER](https://github.com/ElNiak/PANTHER) - PANTHER combines advanced techniques in network protocol verification, integrating the Shadow network simulator with the Ivy formal verification tool. This framework allows for detailed examination of time properties in network protocols and identifies real-world implementation errors. It supports multiple protocols and can simulate advanced persistent threats (APTs) in network protocols.

#### Endpoint
- [OSSEC](https://www.ossec.net/) - An open-source host-based intrusion detection system (HIDS). AI can enhance OSSEC by providing advanced anomaly detection and predictive analysis to identify potential threats before they materialize.

### Detection
#### Network
- [Zeek](https://github.com/zeek/zeek) - A powerful network analysis framework focused on security monitoring. AI can be integrated to analyze network traffic patterns and detect anomalies indicative of security threats.
- [AIEngine](https://github.com/camp0/aiengine) - Next-generation interactive/programmable packet inspection engine with IDS functionality. AIEngine uses machine learning to improve packet inspection and anomaly detection, adapting to new threats over time.

#### Endpoint
- [Sophos Intercept X](https://www.sophos.com/en-us/products/intercept-x.aspx) - Advanced endpoint protection combining traditional signature-based detection with AI-powered behavioral analysis to detect and prevent malware and ransomware attacks.
- [MARK](https://gitlab.cylab.be/cylab/mark) - The multi-agent ranking framework (MARK) aims to provide all the building blocks required to build large-scale detection and ranking systems. It includes distributed storage suited for BigData applications, a web-based visualization and management interface, a distributed execution framework for detection algorithms, and an easy-to-configure triggering mechanism. This allows data scientists to focus on developing effective detection algorithms.

### Response
#### Network
- [Metasploit](https://www.metasploit.com/) - A tool for developing and executing exploit code against a remote target machine. AI can be used to automate the selection of exploits and optimize the attack vectors based on target vulnerabilities.
- [PentestGPT](https://github.com/hackerai-tech/PentestGPT) - PentestGPT provides advanced AI and integrated tools to help security teams conduct comprehensive penetration tests effortlessly. Scan, exploit, and analyze web applications, networks, and cloud environments with ease and precision, without needing expert skills.

#### Endpoint
- [Cortex](https://github.com/TheHive-Project/Cortex) - A powerful and flexible observable analysis and active response engine. AI can be used in Cortex to automate the analysis of observables and enhance threat detection capabilities.

### Monitoring/Scanning
#### Network
- [Nmap](https://nmap.org) - A free and open-source network scanner used to discover hosts and services on a computer network. AI can enhance Nmap's capabilities by automating the analysis of scan results and suggesting potential security weaknesses.

#### Endpoint
- [Burp Suite](https://portswigger.net/burp) - A leading range of cybersecurity tools, brought to you by PortSwigger. Burp Suite can integrate AI to automate vulnerability detection and improve the efficiency of web application security testing.
- [Nikto](https://github.com/sullo/nikto) - An open-source web server scanner which performs comprehensive tests against web servers for multiple items. AI can help Nikto by automating the identification of complex vulnerabilities and enhancing detection accuracy.

#### User
- [MISP](https://www.misp-project.org/) - Open source threat intelligence platform for gathering, sharing, storing, and correlating Indicators of Compromise (IoCs). AI can enhance the efficiency of threat detection and response by automating data analysis and correlation.
- [Scammer-List](https://scammerlist.now.sh/) - A free open source AI based Scam and Spam Finder with a free API

### Tutorials and Guides

- [Review - machine learning techniques applied to cybersecurity](https://link.springer.com/article/10.1007/s13042-018-00906-1)
- [Cybersecurity data science - an overview from machine learning perspective](https://link.springer.com/article/10.1186/s40537-020-00318-5)
- [Machine learning approaches to IoT security - A systematic literature review](https://www.sciencedirect.com/science/article/pii/S2542660521000093)
- [AI infosec - first strikes, zero-day markets, hardware supply chains, adoption barriers](https://www.lesswrong.com/posts/kvk2ZorXui4YB4zvc/ai-infosec-first-strikes-zero-day-markets-hardware-supply)
- [AI Safety in a World of Vulnerable Machine Learning Systems](https://www.lesswrong.com/posts/ncsxcf8CkDveXBCrA/ai-safety-in-a-world-of-vulnerable-machine-learning-systems-1)

#### Certifications
- [IBM Cybersecurity Analyst](https://www.coursera.org/professional-certificates/ibm-cybersecurity-analyst?utm_medium=sem&utm_source=gg&utm_campaign=b2c_emea_ibm-cybersecurity-analyst_ibm_ftcof_professional-certificates_arte_jan_24_dr_geo-multi_sem_rsa_gads_lg-all&campaignid=20963170017&adgroupid=159756465524&device=c&keyword=cybersecurity%20course&matchtype=p&network=g&devicemodel=&adposition=&creativeid=706156862048&hide_mobile_promo=&gad_source=1) - Get ready to launch your career in cybersecurity. Build job-ready skills for an in-demand role in the field, no degree or prior experience required.

## Securing AI SaaS

### Best Practices
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework) - A framework for managing risks associated with AI in SaaS. It provides guidelines on how to implement AI securely, focusing on risk assessment, mitigation, and governance.

### Case Studies
- [Microsoft AI Security](https://www.microsoft.com/en-us/security/ai) - Case studies on securing AI applications in SaaS environments. These case studies demonstrate how AI can be used to enhance security and protect against evolving threats.
- [Google AI Security](https://cloud.google.com/security/ai) - Insights and case studies from Google on how to secure AI applications in the cloud.

### Tools
- [IBM Watson](https://www.ibm.com/security/artificial-intelligence) - Tools and solutions for securing AI applications. Watson uses AI to analyze vast amounts of security data and identify potential threats, providing actionable insights for cybersecurity professionals.
- [Azure Security Center](https://azure.microsoft.com/en-us/services/security-center/) - Comprehensive security management system for cloud environments. AI and machine learning are used to identify threats and vulnerabilities in real-time.

### Network Protection
Machine learning in network security focuses on Network Traffic Analytics (NTA) to analyze traffic and detect anomalies and attacks.

**Examples of ML techniques:**
- Regression to predict network packet parameters and compare them with normal values.
- Classification to identify different classes of network attacks.
- Clustering for forensic analysis.

**Research Papers:**
- [Machine Learning Techniques for Intrusion Detection](https://arxiv.org/abs/1312.2177v2) - A comprehensive survey on various ML techniques used for intrusion detection.
- [A Survey of Network Anomaly Detection Techniques](https://www.gta.ufrj.br/~alvarenga/files/CPE826/Ahmed2016-Survey.pdf) - Discusses various techniques and methods for detecting anomalies in network traffic.
- [Shallow and Deep Networks Intrusion Detection System - A Taxonomy and Survey](https://arxiv.org/abs/1701.02145v1) - A taxonomy and survey of shallow and deep learning techniques for intrusion detection.
- [A Taxonomy and Survey of Intrusion Detection System Design Techniques, Network Threats and Datasets](https://arxiv.org/pdf/1806.03517v1.pdf) - An in-depth review of IDS design techniques and relevant datasets.

### Endpoint Protection
Machine learning applications for endpoint protection can vary depending on the type of endpoint.

**Common tasks:**
- Regression to predict the next system call for executable processes.
- Classification to categorize programs into malware, spyware, or ransomware.
- Clustering for malware detection on secure email gateways.

**Research Papers:**
- [Deep Learning at the Shallow End - Malware Classification for Non-Domain Experts](https://arxiv.org/abs/1807.08265v1) - Discusses deep learning techniques for malware classification.
- [Malware Detection by Eating a Whole EXE](https://arxiv.org/pdf/1710.09435v1.pdf) - Presents a method for detecting malware by analyzing entire executable files.

### Application Security
Machine learning can be applied to secure web applications, databases, ERP systems, and SaaS applications.

**Examples:**
- Regression to detect anomalies in HTTP requests.
- Classification to identify known attack types.
- Clustering user activity to detect DDOS attacks.

**Research Papers:**
- [Adaptively Detecting Malicious Queries in Web Attacks](https://arxiv.org/pdf/1701.07774.pdf) - Proposes methods for detecting malicious web queries.

### User Behavior Analysis
User behavior analysis involves detecting anomalies in user actions, which is often an unsupervised learning problem.

**Tasks:**
- Regression to detect anomalies in user actions.
- Classification for peer-group analysis.
- Clustering to identify outlier user groups.

**Research Papers:**
- [Detecting Anomalous User Behavior Using an Extended Isolation Forest Algorithm](https://arxiv.org/abs/1609.06676) - Discusses an extended isolation forest algorithm for detecting anomalous user behavior.

### Process Behavior (Fraud Detection)
Process behavior monitoring involves detecting anomalies in business processes to identify fraud.

**Tasks:**
- Regression to predict user actions and detect outliers.
- Classification to identify known fraud types.
- Clustering to compare business processes and detect outliers.

**Research Papers:**
- [A Survey of Credit Card Fraud Detection Techniques](https://arxiv.org/abs/1611.06439v1) - A survey on various techniques for credit card fraud detection.
- [Anomaly Detection in Industrial Control Systems Using CNNs](https://arxiv.org/abs/1806.08110v1) - Discusses the use of convolutional neural networks for anomaly detection in industrial control systems.

### Intrusion Detection and Prevention Systems (IDS/IPS)
IDS/IPS systems detect and prevent malicious network activities using machine learning to reduce false positives and improve accuracy.

**Research Papers:**
- [Next-Generation Intrusion Detection Systems](https://www.sciencedirect.com/science/article/abs/pii/S1574013716300153) - Discusses advancements in intrusion detection systems.

### Books & Survey Papers
#### Books
- [AI for Cybersecurity by Cylance (2017)](https://www.blackberry.com/us/en/forms/cylance/gated-content/introduction-to-ai-book) - An introduction to AI for cybersecurity by Cylance.
- [Machine Learning and Security](https://www.oreilly.com/library/view/machine-learning-and/9781491979891/) - Discusses the application of machine learning in security.
- [Mastering Machine Learning for Penetration Testing](https://www.packtpub.com/product/mastering-machine-learning-for-penetration-testing/9781788997409) - A guide on using machine learning for penetration testing.
- [Malware Data Science](https://nostarch.com/malwaredatascience) - Covers data science techniques for malware analysis.
- [AI for Cybersecurity - A Handbook of Use Cases](https://psucybersecuritylab.github.io/) - A handbook on various use cases of AI in cybersecurity.

#### Survey Papers
- [Deep Learning Algorithms for Cybersecurity Applications - A Technological and Status Review](https://www.sciencedirect.com/science/article/pii/S1574013720304172) - Reviews the state of deep learning algorithms in cybersecurity applications.
- [Machine Learning and Cybersecurity - Hype and Reality](https://cset.georgetown.edu/publication/machine-learning-and-cybersecurity/) - Discusses the real-world applications and limitations of machine learning in cybersecurity.

### Offensive Tools and Frameworks
#### Generic Tools
- [Deep-pwning](https://github.com/cchio/deep-pwning) - A lightweight framework for evaluating machine learning model robustness against adversarial attacks.
- [Counterfit](https://github.com/Azure/counterfit) - An automation layer for assessing the security of machine learning systems.
- [DeepFool](https://github.com/lts4/deepfool) - A method to fool deep neural networks.
- [garak](https://github.com/leondz/garak/) - A security probing tool for large language models (LLMs).
- [Snaike-MLflow](https://github.com/protectai/Snaike-MLflow) - A suite of red team tools for MLflow.
- [HackGPT](https://github.com/NoDataFound/hackGPT) - A tool leveraging ChatGPT for hacking purposes.
- [HackingBuddyGPT](https://github.com/ipa-lab/hackingBuddyGPT) - An automated penetration tester.
- [Charcuterie](https://github.com/moohax/Charcuterie) - Code execution techniques for machine learning libraries.

### Adversarial Tools
- [Exploring the Space of Adversarial Images](https://github.com/tabacof/adversarial) - A tool to experiment with adversarial images.
- [Adversarial Machine Learning Library (Ad-lib)](https://github.com/vu-aml/adlib) - A game-theoretic library for adversarial machine learning.
- [EasyEdit](https://github.com/zjunlp/EasyEdit) - A tool to modify the ground truths of large language models (LLMs).

### Poisoning Tools
- [BadDiffusion](https://github.com/IBM/BadDiffusion) - Official repository to reproduce the paper "How to Backdoor Diffusion Models?" published at CVPR 2023.

### Privacy Tools
- [PrivacyRaven](https://github.com/trailofbits/PrivacyRaven) - A privacy testing library for deep learning systems.

### Defensive Tools and Frameworks
#### Safety and Prevention
- [Guardrail.ai](https://shreyar.github.io/guardrails/) - A Python package to add structure, type, and quality guarantees to the outputs of large language models (LLMs).

#### Detection Tools
- [ProtectAI's model scanner](https://github.com/protectai/model-scanner) - A security scanner for detecting suspicious actions in serialized ML models.
- [rebuff](https://github.com/woop/rebuff) - A prompt injection detector.
- [langkit](https://github.com/whylabs/langkit) - A toolkit for monitoring language models and detecting attacks.
- [StringSifter](https://github.com/fireeye/stringsifter) - A tool that ranks strings based on their relevance for malware analysis.

#### Privacy and Confidentiality
- [Python Differential Privacy Library](https://github.com/OpenMined/PyDP) - A library for implementing differential privacy.
- [Diffprivlib](https://github.com/IBM/differential-privacy-library) - IBM's differential privacy library.
- [PLOT4ai](https://plot4.ai/) - A threat modeling library for building responsible AI.
- [TenSEAL](https://github.com/OpenMined/TenSEAL) - A library for performing homomorphic encryption operations on tensors.
- [SyMPC](https://github.com/OpenMined/SyMPC) - A secure multiparty computation library.
- [PyVertical](https://github.com/OpenMined/PyVertical) - Privacy-preserving vertical federated learning.
- [Cloaked AI](https://ironcorelabs.com/products/cloaked-ai/) - Open source property-preserving encryption for vector embeddings.

### Resources for Learning
- [MLSecOps podcast](https://mlsecops.com/podcast) - A podcast dedicated to the intersection of machine learning and security operations.

### Uncategorized Useful Resources
- [OWASP ML TOP 10](https://owasp.org/www-project-machine-learning-security-top-10/) - The top 10 machine learning security risks identified by OWASP.
- [OWASP LLM TOP 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) - The top 10 security risks for large language models as identified by OWASP.
- [OWASP AI Security and Privacy Guide](https://owasp.org/www-project-ai-security-and-privacy-guide/) - A guide to securing AI systems and ensuring privacy.
- [OWASP WrongSecrets LLM exercise](https://wrongsecrets.herokuapp.com/challenge/32) - An exercise for testing AI model security.
- [NIST AIRC](https://airc.nist.gov/Home) - NIST Trustworthy & Responsible AI Resource Center.
- [ENISA Multilayer Framework for Good Cybersecurity Practices for AI](https://www.enisa.europa.eu/publications/multilayer-framework-for-good-cybersecurity-practices-for-ai) - A framework for good cybersecurity practices in AI.
- [The MLSecOps Top 10](https://ethical.institute/security.html) - Top 10 security practices for machine learning operations.

### Research Papers
#### Adversarial Examples and Attacks
- [High Dimensional Spaces, Deep Learning and Adversarial Examples](https://arxiv.org/abs/1801.00634) - Discusses the challenges of adversarial examples in high-dimensional spaces.
- [Adversarial Task Allocation](https://arxiv.org/abs/1709.00358) - Explores adversarial task allocation in machine learning systems.
- [Robust Physical-World Attacks on Deep Learning Models](https://arxiv.org/abs/1707.08945) - Examines physical-world attacks on deep learning models.
- [The Space of Transferable Adversarial Examples](https://arxiv.org/abs/1704.03453) - Discusses transferable adversarial examples in deep learning.
- [RHMD - Evasion-Resilient Hardware Malware Detectors](http://www.cs.ucr.edu/~kkhas001/pubs/micro17-rhmd.pdf) - Explores hardware-based malware detectors resilient to evasion.
- [Vulnerability of Deep Reinforcement Learning to Policy Induction Attacks](https://arxiv.org/abs/1701.04143) - Examines policy induction attacks on deep reinforcement learning models.
- [Can you fool AI with adversarial examples on a visual Turing test?](https://arxiv.org/abs/1709.08693) - Tests the robustness of AI models using a visual Turing test.
- [Explaining and Harnessing Adversarial Examples](https://arxiv.org/abs/1412.6572) - A foundational paper on adversarial examples in machine learning.
- [Delving into Adversarial Attacks on Deep Policies](https://arxiv.org/abs/1705.06452) - Analyzes adversarial attacks on deep policies.
- [Crafting Adversarial Input Sequences for Recurrent Neural Networks](https://arxiv.org/abs/1604.08275) - Discusses adversarial attacks on RNNs.
- [Practical Black-Box Attacks against Machine Learning](https://arxiv.org/abs/1602.02697) - Explores practical black-box attacks on machine learning models.
- [Generating Adversarial Malware Examples for Black-Box Attacks Based on GAN](https://arxiv.org/abs/1702.05983) - Uses GANs to generate adversarial malware examples.
- [Data Driven Exploratory Attacks on Black Box Classifiers in Adversarial Domains](https://arxiv.org/abs/1703.07909) - Explores data-driven attacks on black-box classifiers.
- [Fast Feature Fool - A Data-Independent Approach to Universal Adversarial Perturbations](https://arxiv.org/abs/1707.05572v1) - Proposes a method for creating universal adversarial perturbations.
- [Simple Black-Box Adversarial Perturbations for Deep Networks](https://arxiv.org/abs/1612.06299) - Discusses simple methods for black-box adversarial perturbations.
- [Wild Patterns - Ten Years After the Rise of Adversarial Machine Learning](https://arxiv.org/abs/1712.03141) - A retrospective on the evolution of adversarial machine learning.
- [One Pixel Attack for Fooling Deep Neural Networks](https://arxiv.org/abs/1710.08864v1) - Demonstrates how a single-pixel modification can fool deep neural networks.
- [FedMLSecurity - A Benchmark for Attacks and Defenses in Federated Learning and LLMs](https://arxiv.org/abs/2306.04959) - A benchmark for evaluating the security of federated learning and LLMs.
- [Jailbroken - How Does LLM Safety Training Fail?](https://arxiv.org/abs/2307.02483) - Analyzes the failure modes of LLM safety training.
- [Bad Characters - Imperceptible NLP Attacks](https://arxiv.org/abs/2106.09898) - Discusses imperceptible adversarial attacks on NLP models.
- [Universal and Transferable Adversarial Attacks on Aligned Language Models](https://arxiv.org/abs/2307.15043) - Explores universal adversarial attacks on language models.
- [Exploring the Vulnerability of Natural Language Processing Models via Universal Adversarial Texts](https://aclanthology.org/2021.alta-1.14/) - Investigates the vulnerability of NLP models to adversarial texts.
- [Adversarial Examples Are Not Bugs, They Are Features](https://arxiv.org/abs/1905.02175) - Argues that adversarial examples are inherent features of models.
- [Adversarial Attacks on Tables with Entity Swap](https://ceur-ws.org/Vol-3462/TADA4.pdf) - Discusses adversarial attacks on tabular data.
- [Here Comes the AI Worm - Unleashing Zero-click Worms that Target GenAI-Powered Applications](https://arxiv.org/abs/2403.02817) - Explores zero-click worms targeting AI-powered applications.

#### Model Extraction
- [Stealing Machine Learning Models via Prediction APIs](https://arxiv.org/abs/1609.02943) - Discusses methods for extracting machine learning models via prediction APIs.
- [On the Risks of Stealing the Decoding Algorithms of Language Models](https://arxiv.org/abs/2303.04729) - Investigates the risks of extracting decoding algorithms from language models.

#### Evasion
- [Adversarial Demonstration Attacks on Large Language Models](https://arxiv.org/abs/2305.14950) - Explores evasion attacks on large language models.
- [Looking at the Bag is not Enough to Find the Bomb - An Evasion of Structural Methods for Malicious PDF Files Detection](https://pralab.diee.unica.it/sites/default/files/maiorca_ASIACCS13.pdf) - Discusses evasion of PDF malware detection methods.
- [Adversarial Generative Nets - Neural Network Attacks on State-of-the-Art Face Recognition](https://arxiv.org/abs/1801.00349) - Investigates adversarial attacks on face recognition models.
- [Query Strategies for Evading Convex-Inducing Classifiers](https://people.eecs.berkeley.edu/~adj/publications/paper-files/1007-0484v1.pdf) - Discusses query strategies for evading convex-inducing classifiers.
- [Adversarial Prompting for Black Box Foundation Models](https://arxiv.org/abs/2302.04237) - Explores adversarial prompting for foundation models.
- [Automatically Evading Classifiers - A Case Study on PDF Malware Classifiers](http://evademl.org/docs/evademl.pdf) - Case study on evading PDF malware classifiers.
- [Generic Black-Box End-to-End Attack against RNNs and Other API Calls Based Malware Classifiers](https://arxiv.org/abs/1707.05970) - Investigates black-box attacks on RNNs and malware classifiers.
- [GPTs Don't Keep Secrets - Searching for Backdoor Watermark Triggers in Autoregressive Language Models](https://aclanthology.org/2023.trustnlp-1.21/) - Investigates backdoor triggers in autoregressive language models.

#### Poisoning
- [Instructions as Backdoors - Backdoor Vulnerabilities of Instruction Tuning for Large Language Models](https://arxiv.org/abs/2305.14710) - Discusses backdoor vulnerabilities in instruction-tuned language models.
- [BadGPT - Exploring Security Vulnerabilities of ChatGPT via Backdoor Attacks to InstructGPT](https://arxiv.org/abs/2304.12298) - Explores backdoor attacks on ChatGPT.
- [Towards Poisoning of Deep Learning Algorithms with Back-Gradient Optimization](https://arxiv.org/abs/1708.08689) - Proposes back-gradient optimization for poisoning deep learning algorithms.
- [Efficient Label Contamination Attacks Against Black-Box Learning Models](https://www.ijcai.org/proceedings/2017/0551.pdf) - Discusses efficient label contamination attacks on black-box models.
- [Text-to-Image Diffusion Models Can be Easily Backdoored through Multimodal Data Poisoning](https://arxiv.org/abs/2305.04175) - Explores backdooring diffusion models through data poisoning.
- [UOR - Universal Backdoor Attacks on Pre-Trained Language Models](https://arxiv.org/abs/2305.09574) - Discusses universal backdoor attacks on language models.
- [Analyzing And Editing Inner Mechanisms of Backdoored Language Models](http://arxiv.org/abs/2302.12461) - Investigates the inner mechanisms of backdoored language models.
- [Instructions as Backdoors - Backdoor Vulnerabilities of Instruction Tuning for Large Language Models](https://arxiv.org/abs/2305.14710) - Discusses backdoor vulnerabilities in instruction-tuned language models.
- [How to Backdoor Diffusion Models?](https://arxiv.org/abs/2212.05400) - Explores methods for backdooring diffusion models.
- [On the Exploitability of Instruction Tuning](https://arxiv.org/abs/2306.17194) - Discusses the exploitability of instruction tuning.
- [Defending against Insertion-based Textual Backdoor Attacks via Attribution](https://aclanthology.org/2023.findings-acl.561/) - Proposes defenses against textual backdoor attacks.
- [A Gradient Control Method for Backdoor Attacks on Parameter-Efficient Tuning](https://aclanthology.org/2023.acl-long.194/) - Discusses gradient control methods for backdoor attacks.
- [BadNL - Backdoor Attacks Against NLP Models with Semantic-Preserving Improvements](https://arxiv.org/abs/2006.01043) - Explores semantic-preserving backdoor attacks on NLP models.
- [Be Careful About Poisoned Word Embeddings - Exploring the Vulnerability of the Embedding Layers in NLP Models](https://arxiv.org/abs/2103.15543) - Discusses the vulnerability of word embeddings to poisoning.
- [BadPrompt - Backdoor Attacks on Continuous Prompts](https://arxiv.org/abs/2211.14719) - Investigates backdoor attacks on continuous prompts.

### Privacy
- [Extracting Training Data from Diffusion Models](https://arxiv.org/abs/2301.13188) - Discusses the extraction of training data from diffusion models.
- [Prompt Stealing Attacks Against Text-to-Image Generation Models](https://arxiv.org/abs/2305.13873) - Explores prompt stealing attacks on text-to-image generation models.
- [Are Diffusion Models Vulnerable to Membership Inference Attacks?](https://arxiv.org/abs/2302.01316) - Investigates the vulnerability of diffusion models to membership inference attacks.
- [Model Inversion Attacks that Exploit Confidence Information and Basic Countermeasures](https://www.cs.cmu.edu/~mfredrik/papers/fjr2015ccs.pdf) - Discusses model inversion attacks and countermeasures.
- [Multi-Step Jailbreaking Privacy Attacks on ChatGPT](http://arxiv.org/abs/2304.05197) - Explores multi-step jailbreaking privacy attacks on ChatGPT.
- [Flocks of Stochastic Parrots - Differentially Private Prompt Learning for Large Language Models](https://arxiv.org/abs/2305.15594) - Discusses differentially private prompt learning for language models.
- [ProPILE - Probing Privacy Leakage in Large Language Models](https://arxiv.org/abs/2307.01881) - Investigates privacy leakage in large language models.
- [Sentence Embedding Leaks More Information than You Expect - Generative Embedding Inversion Attack to Recover the Whole Sentence](https://arxiv.org/pdf/2305.03010.pdf) - Discusses embedding inversion attacks on sentence embeddings.
- [Text Embeddings Reveal (Almost) As Much As Text](https://arxiv.org/pdf/2310.06816.pdf) - Explores the information leakage of text embeddings.
- [Vec2Face - Unveil Human Faces from Their Blackbox Features in Face Recognition](https://arxiv.org/pdf/2003.06958.pdf) - Discusses the reconstruction of human faces from face recognition features.
- [Realistic Face Reconstruction from Deep Embeddings](https://openreview.net/pdf?id=-WsBmzWwPee) - Explores face reconstruction from deep embeddings.

#### Injection
- [DeepPayload - Black-box Backdoor Attack on Deep Learning Models through Neural Payload Injection](https://arxiv.org/abs/2101.06896) - Discusses backdoor attacks on deep learning models through neural payload injection.
- [Not What You've Signed Up For - Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection](https://arxiv.org/abs/2302.12173) - Discusses indirect prompt injection attacks on LLM-integrated applications.
- [Latent Jailbreak - A Benchmark for Evaluating Text Safety and Output Robustness of Large Language Models](https://arxiv.org/abs/2307.08487) - Proposes a benchmark for evaluating the safety and robustness of large language models.
- [Jailbreaker - Automated Jailbreak Across Multiple Large Language Model Chatbots](https://arxiv.org/abs/2307.08715) - Discusses automated jailbreak attacks on multiple large language model chatbots.
- [(Ab)using Images and Sounds for Indirect Instruction Injection in Multi-Modal LLMs](https://arxiv.org/abs/2307.10490) - Explores indirect instruction injection using images and sounds in multi-modal LLMs.

#### Other Research Papers
- [Summoning Demons - The Pursuit of Exploitable Bugs in Machine Learning](https://arxiv.org/abs/1701.04739) - Discusses the pursuit of exploitable bugs in machine learning.
- [capAI - A Procedure for Conducting Conformity Assessment of AI Systems in Line with the EU Artificial Intelligence Act](https://papers.ssrn.com/sol3/papers.cfm?abstract_id=4064091) - Proposes a procedure for AI system conformity assessment.
- [A Study on Robustness and Reliability of Large Language Model Code Generation](https://arxiv.org/abs/2308.10335) - Investigates the robustness and reliability of LLM code generation.
- [Getting pwn'd by AI - Penetration Testing with Large Language Models](https://arxiv.org/abs/2308.00121) - Explores penetration testing with large language models.
- [Evaluating LLMs for Privilege-Escalation Scenarios](https://arxiv.org/abs/2310.11409) - Evaluates LLMs for privilege-escalation scenarios.
