# Type 1 TShoot
Powershell module that provides functions for troubleshooting type 1 system issues.

## Usage
The module must be imported on the machine you wish to troubleshoot (the machine must be running Windows 10/11).  After the module is imported there are two troubleshooting scripts that can be run.

### Rum-PICOMTroubleShooting

**Must be run as Admin!**
This cmdlet will run all of the tests in the module.  This command is meant to be run by staff who have experience installing and configureing the PICOM application.  Most of the outuput would not make sense to someone without PICOM experience.

After the test run is compolete the results will be uploaded to Azure blob storage as a text file so they can be reviewed by other staff or attached to tickets.

### Run-UserTests
This cmdlet will run a subset of the tests in the module that are readable and actionable by an end user.  Output is color coded (green means good, red means bad) so a user can know if everything has passed without having to read full messages.
