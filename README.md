# PatchScout

Reproduce the baseline named PatchScout which is a model published on CCS'21.

Their publication: [Locating the Security Patches for Disclosed OSS Vulnerabilities with Vulnerability-Commit Correlation Ranking](https://dl.acm.org/doi/10.1145/3460120.3484593#)


---

Note: This repository is a part of our research [PatchFinder](https://github.com/MarkLee131/PatchFinder), published at ISSTA 2024. 

## PatchFinder [![arXiv](https://img.shields.io/badge/arXiv-<2407.17065>-<COLOR>.svg)](https://arxiv.org/abs/2407.17065) [![Visit Our Website](https://img.shields.io/badge/Google_Site-_PatchFinder-blue)](https://sites.google.com/view/issta2024-patchfinder/home) ![](https://img.shields.io/badge/CCF-A-red?style=flat-square) [![](https://img.shields.io/badge/ISSTA-2024-blue?style=flat-square)](https://2024.issta.org/)

## Cite us
Please cite us if this repository helps. :)
### BibTeX

```
@inproceedings{li2024patchfinder,
  title={PatchFinder: A Two-Phase Approach to Security Patch Tracing for Disclosed Vulnerabilities in Open Source Software},
  author={Li, Kaixuan and Zhang, Jian and Chen, Sen and Liu, Han and Liu, Yang and Chen, Yixiang},
  booktitle={Proceedings of the 33rd ACM SIGSOFT International Symposium on Software Testing and Analysis},
  year={2024}
}
```

## Structure

```
PatchScout/
├── encoding_module.py
├── feature.py
├── LICENSE
├── patchscout.py
├── README.md
├── test685.json
|── train943.xlsx
├── utils.py
└── vuln_type_impact.json
```

```bash
PatchScout/
├── code_data.py
├── collect_data.py: collcect data for training and testing (first used)
├── commit_data.py
├── encoding_module.py
├── feature_msg.py
├── feature.py
├── LICENSE
├── msg_data.py
├── patchscout.py
├── process_data.py
├── README.md
├── test.py
└── utils.py
```




## Usage

## License

The PatchScout is licensed and distributed under the [GNU GPLv3](LICENSE) license. Contact us if your are looking for an exception to the terms.
