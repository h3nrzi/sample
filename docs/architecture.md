# Lightweight Packet Filter Firewall

## Stage 1 – Requirements Analysis (summary)
- **Goals:** Lightweight IPv4 packet filter in C99 on Linux (Ubuntu/Debian), filtering by IP/port/protocol, with allow/deny rules, logging, rate limiting (e.g., SYN flood), config-driven behavior, optional daemon mode.
- **Capture:** Raw AF_PACKET socket (SOCK_RAW, ETH_P_ALL), manual parsing of Ethernet/IP/TCP/UDP/ICMP; no libpcap dependency unless required.
- **Performance & Safety:** Modular design, O(n) rule matching or better, strict memory management (no leaks/overflows), robust error handling, minimal dependencies.
- **Operational Needs:** Foreground/daemon execution, clear logging format, configurable default policy, concise rule syntax, configurable rate-limit knobs, Makefile build, tests and documentation.

## Stage 2 – High-Level Architecture
The firewall is organized into cooperating modules with clear responsibilities and boundaries. Communication flows through explicit interfaces to keep the system testable and maintainable.

### Component Overview
1. **Core Event Loop**
   - Drives packet reception via `select()`/`poll()` on the raw socket.
   - Invokes decoding, rule evaluation, rate limiting, and actions (drop/accept) per packet.
   - Handles graceful shutdown signals and timed tasks (e.g., cleaning rate-limit buckets).

2. **Packet Capture Module**
   - Initializes AF_PACKET raw socket bound to a configured network interface and protocol `ETH_P_ALL`.
   - Receives Ethernet frames into bounded buffers; validates lengths; parses Ethernet → IPv4 → TCP/UDP/ICMP headers.
   - Produces a normalized `packet_info` structure handed to the Rule Engine.

3. **Rule Engine**
   - Holds an ordered list of rules (first-match semantics) with fields: src/dst IP (CIDR), src/dst port ranges, protocol, action (ALLOW/DENY), optional rate-limit binding, and rule ID/description.
   - Evaluates incoming `packet_info` against rules in O(n); default policy applied if no match.
   - Emits a decision object (action, matched rule ID, logging flags).

4. **Config Parser**
   - Loads a text config at startup (and optional reload signal) defining global settings (interface, default policy, log path/level, rate-limit parameters) and rule list.
   - Performs validation: syntax, ranges, CIDR correctness, duplicate rule IDs.
   - Produces in-memory structures consumed by Rule Engine and Logger.

5. **Logger**
   - Provides timestamped, thread-safe logging to file (and optionally syslog) with severity levels.
   - Standard log line includes: timestamp, action (ALLOW/DENY), src/dst IP:port, protocol, rule ID, reason/error, packet flags (e.g., TCP SYN), and rate-limit status.

6. **Rate Limiter**
   - Token-bucket or fixed-window counters keyed by tuple (e.g., src IP, src+dst, or rule ID) to mitigate floods (e.g., TCP SYN).
   - Interacts with Rule Engine to decide drop/allow when limits exceed thresholds.
   - Periodic cleanup to remove stale entries.

7. **Daemon/CLI Wrapper (optional)**
   - Handles daemonization (fork, setsid, stdio redirection), PID file management, and signal handling (SIGHUP reload, SIGTERM shutdown).
   - Provides command-line options for config path, interface, foreground/daemon mode, and log verbosity.

### Data Flow
1. **Startup:** CLI parses options → Config Parser loads settings → Logger initializes → Packet Capture sets up raw socket → Rate Limiter initializes state → Rule Engine receives rule set.
2. **Runtime loop:** Event loop waits on socket → Packet Capture reads frame → parses into `packet_info` → Rule Engine matches rules and consults Rate Limiter → action determined → Logger records decision → optional counter updates.
3. **Shutdown/Reload:** Signals trigger cleanup (close sockets, flush logs, free rule/rate-limit tables). Reload re-runs Config Parser and swaps in new rule sets atomically.

### Threading Model
- Default single-threaded event loop for simplicity and determinism; eliminates locking in hot path except for logging (can use buffered async logging later if needed).
- Optional future extension: dedicated logging thread with message queue; rate limiter cleanup via periodic timer (non-blocking in main loop).

### Error Handling & Safety
- Every syscall checked; failures logged with errno descriptions.
- Bounded buffers for packet capture to avoid overreads; length checks before header access.
- All heap allocations paired with frees; module init/teardown sequences well-defined.

### Extensibility Notes
- IPv6 support can be added by extending parser and rule fields.
- Additional protocols or stateful tracking can build on the same module boundaries.

## Next Steps (pending approval)
Proceed to Stage 3: design of data structures (rule structs, packet structs, logger config, rate-limit buckets) and start defining header file outlines for each module.
