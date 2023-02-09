# EDR-NT-Hooks
A method for seeing the function that are potentially hooked the EDR system.
Checks for NT potentially hooked calls by the EDR system by looking at the inital sys stub
``` 4c 8b d1 b8 ```

## False Positives
There are a few false positives that might occur for the following functions
