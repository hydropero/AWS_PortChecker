# AWS Port Checker
### This project was created to help identify which ports are being left open unnecessarily either on EC2 instances or within the Linux distro running on the instance.
<br>
Script creates two ASCII tables. The first provides the following information, with each row containing one security group rule. The second contains only results where ports were left open via the applied security group for instance, that aren't also open on the Linux OS hosted on the instance.

<br>

This information when retrieved from the API is structured hierarchically, and must be flatted to be presented in table format (by far the most challenging portion of the project).

<br>

Be sure to change out the location specified for your SSH key, and the AWS CLI must be configured on your PC as well. Screenshots available below.

<br>

## Table1
![AWS_ALL_ITEMS](https://github.com/hydropero/AWS_PortChecker/blob/Main/images/Screen%20Shot%202023-02-10%20at%207.33.17%20AM.png?raw=true)

<br>
<br>

## Table2
<img src="https://github.com/hydropero/AWS_PortChecker/blob/Main/images/Screen%20Shot%202023-02-15%20at%207.14.30%20PM.png?raw=true"  width="50%" height="25%">
