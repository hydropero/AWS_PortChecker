# AWS Port Checker
### This project was created to help identify which ports are being left open unnecessarily either on EC2 instances or within the Linux distro running on the instance.

Script creates two ASCII tables. The first provides the following information, with each row containing one security group rule. The second contains only results where ports were left open via the applied security group for instance, that aren't also open on the Linux OS hosted on the instance.


This information when retrieved from the API is structured hierarchically, and must be flatted to be presented in table format (by far the most challening portion of the project).

Be sure to change out the location specified for your SSH key, and the AWS CLI must be configured on your PC as well. Screenshots available below.

[AWS_ALL]()
