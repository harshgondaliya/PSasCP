## In-Network Computing System for Switch/Router Co-Processors
### Introduction
This repository contains the source code files for the implementation of our proposed secure in-network computing system. The system is based on a simple reduced instruction set architecture and it exploits capabilities of upcoming generations of packet processing pipelines in programmable network switches. This instruction set enables processing of data at multiple terabits-per-second. 

Instructions for regular expressions, basic arithmetic and logical operations have been implemented as proof of concept. A packet containing both instruction and data blocks are presented as an input to the pipeline by bundling both the function and its arguments into the packet.

### Source Code Directories

`BMv2/` implementation for BMv2 simple_switch target 

`NetFPGA/TBL-PSasCP/` implementation for NetFPGA SUME platform  using match-action tables

`NetFPGA/IF-PSasCP/` implementation for NetFPGA SUME platform using if-else condition blocks 

### Citation Details

This work is published in IEEE Internet of Things Journal. When referencing this work, please use the following citation:

Ganesh C. Sankaran, Krishna M. Sivalingam, Harsh Gondaliya, "P4 and NetFPGA based secure in-network computing architecture for AI-enabled Industrial Internet of Things"

### Acknowledgements
This work was supported by a Mid-Career Institute Research and Development Award (IRDA) from IIT Madras (2017–2020) and DST-FIST grant (SR/FST/ETI-423/2016) from Government of India (2017–2022).
