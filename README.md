# exdbg

exdbg is a Windows debugger based on runtime exceptions.  
It utilizes VEH exception handling to implement breakpoints and stepping.  
It also acts as a GDB server, so you could use it with any debugger with supports remote GDB debugging.  

I created this debugger mainly to debug assembly with IDA in situations where memory editing isn't an option.

# Features
- Backend implementation:
  - VEH Exception Handling
- Frontend implementation:
  - GDB server

# Changelog
## 05/025/2023
  - Initial implementation.
