# EDR-NT-Hooks
A method for discovering functions that are potentially hooked the EDR system.
Checks for NT potentially hooked calls by the EDR system by looking at the inital sys stub
``` 4c 8b d1 b8 ```

## False Positives
There are a few false positives that might occur for the following functions
- NtGetTickCount
- NtQuerySystemTime
- NtdllDefWindowProc_A
- NtdllDefWindowProc_W
- NtdllDialogWndProc_A
- NtdllDialogWndProc_W
- ZwQuerySystemTime

A sample run from Visual Studio - 

![nt](https://user-images.githubusercontent.com/102996033/218040594-39da0a05-0695-443d-b830-5aa0275027d7.png)
