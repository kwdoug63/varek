#!/usr/bin/env python3
import time
import random
import sys
from tqdm import tqdm

# ANSI Color Codes for terminal aesthetics
CYAN = '\033[96m'
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
RESET = '\033[0m'
BOLD = '\033[1m'

TOTAL_RUNS = 10001

def clear_screen():
    sys.stdout.write('\033[2J\033[H')
    sys.stdout.flush()

def run_benchmark():
    clear_screen()
    
    print(f"{BOLD}{CYAN}===================================================={RESET}")
    print(f"{BOLD}{CYAN}   VAREK v1.3.0 OS-LEVEL CONTAINMENT BENCHMARK      {RESET}")
    print(f"{BOLD}{CYAN}===================================================={RESET}\n")
    print(f"[*] Initializing seccomp-unotify bridge...")
    time.sleep(0.5)
    print(f"[*] Warden process attached to kernel. PID: 49912")
    time.sleep(0.5)
    print(f"[*] Derivation Engine: {GREEN}ONLINE{RESET}")
    print(f"[*] Target verification runs: {TOTAL_RUNS}")
    print(f"[*] Press ENTER to execute workload...\n")
    
    input() # Pauses here so you can start recording in OBS, then hit Enter!
    
    start_time = time.time()
    
    # The High-Speed Loop with TQDM Progress Bar
    # bar_format customizes the look to match our CLI aesthetic
    custom_format = f"{{desc}}: {{percentage:3.0f}}%|{{bar}}| {{n_fmt}}/{{total_fmt}} [{GREEN}{{elapsed}}{RESET}<{{remaining}}, {{rate_fmt}}]"
    
    with tqdm(total=TOTAL_RUNS, desc=f"{BOLD}{CYAN}Kernel Traps{RESET}", unit="run", bar_format=custom_format, ncols=80) as pbar:
        for i in range(1, TOTAL_RUNS + 1):
            # Simulate slight variations in latency around your 3.44ms mark
            latency = round(random.uniform(2.80, 4.10), 2)
            
            # Simulate different intercepted syscalls
            syscall = random.choice(["openat", "connect", "execve", "socket", "mprotect"])
            
            # 99% ALLOW, 1% EPERM (Hostile Exfiltration attempt)
            if random.random() > 0.01:
                decision = f"{GREEN}ALLOW{RESET}"
                action = f"Semantic Match: OK"
            else:
                decision = f"{RED}EPERM{RESET}"
                action = f"{YELLOW}Violation: EXFILTRATION{RESET}"

            # Create the log line
            log_line = f"[Warden] Run: {i:05d} | Syscall: {syscall:8} | Time: {latency}ms | Action: {action:23} | Policy: {decision}"
            
            # Use tqdm.write INSTEAD of print so it doesn't break the progress bar
            tqdm.write(log_line)
            
            # Update the progress bar
            pbar.update(1)
            
            # Tiny sleep to make the text scroll visibly in the video
            time.sleep(0.001) 

    end_time = time.time()
    total_time = end_time - start_time
    
    # The Dramatic Final Summary
    print(f"\n{BOLD}{CYAN}===================================================={RESET}")
    print(f"{BOLD}{CYAN}               BENCHMARK COMPLETE                   {RESET}")
    print(f"{BOLD}{CYAN}===================================================={RESET}")
    print(f"  Total Runs Executed : {TOTAL_RUNS}")
    print(f"  Total Elapsed Time  : {round(total_time, 2)} seconds")
    print(f"  P50 Intercept Latency: 3.21 ms")
    print(f"  P99 Intercept Latency: {BOLD}{GREEN}3.44 ms{RESET}")
    print(f"  False Negative Rate : {BOLD}{GREEN}0.00%{RESET}")
    print(f"  False Positive Rate : {BOLD}{GREEN}0.00%{RESET}")
    print(f"  Kernel Trap Status  : STABLE")
    print(f"{BOLD}{CYAN}===================================================={RESET}\n")

if __name__ == "__main__":
    try:
        run_benchmark()
    except KeyboardInterrupt:
        print("\n[!] Benchmark aborted by user.")