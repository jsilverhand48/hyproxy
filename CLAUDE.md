When working in this repo, use Serena's symbol tools (get_symbols_overview,
find_symbol, find_referencing_symbols) to navigate. Do not read whole files
or symbol bodies unless the task requires the implementation. Prefer
symbol-level edits (replace_symbol_body, rename_symbol) over full-file rewrites.

Do not:
- Attempt to run the project
- Configure the system to run the project
- Commit any changes
- read test files, or make assumptions based of test files


## Testing
- Run only the specific test(s) relevant to the change, never the full suite unless I explicitly ask.
- Always use: pytest <path>::<test> -q --tb=short -p no:cacheprovider
- For any run likely to be verbose, redirect and read only the tail:
    pytest <args> > /tmp/pytest.log 2>&1; tail -n 30 /tmp/pytest.log
- The mk-2 / key-rotation e2e tests are order-dependent and flaky. Ignore failures there. Do NOT investigate them or try to prove they are pre-existing.

## Debugging
- ssh into staging to parse logs and check whats wrong using "ssh hyproxy-dev" and then cd into ~/hyproxy
- rebuild after any changes using ./build.sh --clean
- stop all processes using ./stop.sh
- start staging using ./start-staging.sh
- make changes on the remote host
- mirror any changes you make in staging to the local project repo after the goal is achieved
