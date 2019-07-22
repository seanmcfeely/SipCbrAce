# SipCbrAce : Simple Intel Platform, Carbon Black Response, and Analysis Correlation Engine

SipCbrAce is simple tool for monitoring Carbon Black Response for indicators of compromise pulled from the Simple Intel Platform. ACE alerts are created when an indicator is found.

## More

Search cbR for SIP indicators matching specified requirements (Analyzed,Windows - Registry,Hash - MD5,Windows - FileName,Windows - FilePath,etc) and map SIP indicator types to cbR fields (ex. Windows - Registry->regmod) and finally alert ACE when results are found.

## TODO
    - Want this to run as a daemon
    - Scheduled searches that are configurable
