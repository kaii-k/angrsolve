from __future__ import annotations

import logging
import signal
import time
from dataclasses import dataclass, field
from typing import Any, Callable, List, Optional

import angr
import claripy

from angrsolve.inputs import InputSetup, SymbolicFile
from angrsolve.output import Solution

logger = logging.getLogger("angrsolve")


@dataclass
class ExploreConfig:
    """Configuration for the exploration phase."""

    find_addresses: List[int] = field(default_factory=list)
    avoid_addresses: List[int] = field(default_factory=list)
    timeout: Optional[float] = None
    max_depth: Optional[int] = None
    max_active: Optional[int] = None
    max_steps: Optional[int] = None
    veritesting: bool = False
    use_unicorn: bool = False


_EXPLORE_TIMED_OUT = False


def _timeout_handler(signum: int, frame: Any) -> None:
    global _EXPLORE_TIMED_OUT
    _EXPLORE_TIMED_OUT = True
    raise TimeoutError("Exploration timed out")


def _extract_stdin(state: angr.SimState, size: int) -> Optional[bytes]:
    if size == 0:
        return None
    try:
        fd = state.posix.get_fd(0)
        if fd is None:
            return None
        # Data that the program *read* from stdin carries the correct
        # constraints (e.g. from strcmp).  Use read_storage for this.
        rs = fd.read_storage
        if rs is None:
            return None
        content_list = rs.content
        if not content_list:
            return None
        # Concatenate all reads (handles both single fgets and repeated
        # getchar() calls).
        if len(content_list) == 1:
            sym_data = content_list[0][0]
        else:
            sym_data = claripy.Concat(*(c[0] for c in content_list))
        raw = state.solver.eval(sym_data, cast_to=bytes)
        null_idx = raw.find(b"\x00")
        return raw[:null_idx] if null_idx >= 0 else raw
    except Exception as e:
        logger.debug("stdin extraction failed: %s", e)
        return None


def _extract_argv_from_mem(state: angr.SimState, addr: int, size: int) -> Optional[bytes]:
    if size == 0:
        return None
    try:
        raw = state.solver.eval(state.memory.load(addr, size + 1), cast_to=bytes)
        null_idx = raw.find(b"\x00")
        return raw[:null_idx] if null_idx >= 0 else raw.rstrip(b"\x00")
    except Exception as e:
        logger.debug("argv extraction failed: %s", e)
        return None


def _extract_file(state: angr.SimState, sf: SymbolicFile) -> Optional[bytes]:
    if sf.sym_content is None:
        try:
            sim_file_obj = state.fs.get(sf.filename)
            if sim_file_obj is None:
                return None
            return state.solver.eval(sim_file_obj.content, cast_to=bytes)
        except Exception:
            return None
    try:
        raw = state.solver.eval(sf.sym_content, cast_to=bytes)
        null_idx = raw.find(b"\x00")
        return raw[:null_idx] if null_idx >= 0 else raw
    except Exception as e:
        logger.debug("file extraction failed: %s", e)
        return None


def _extract_general(state: angr.SimState) -> Optional[bytes]:
    """Fallback: find printable memory from constrained BVS variables.

    Covers binaries that read from uninitialized local buffers (e.g.
    ``char buf[64]``) that angr fills symbolically.  Looks for
    ``mem_<hexaddr>_<id>_<size>`` variables in solver constraints
    and reads the concrete bytes from the state.
    """
    import re
    try:
        mem_addrs: List[int] = []
        for c in state.solver.constraints:
            for leaf in c.leaf_asts():
                if leaf.op == "BVS":
                    m = re.match(r"mem_([0-9a-f]+)_\d+_\d+", leaf.args[0])
                    if m:
                        addr = int(m.group(1), 16)
                        mem_addrs.append(addr)
        if not mem_addrs:
            return None
        mem_addrs = sorted(set(mem_addrs))
        # Find the longest contiguous run of addresses.
        best: Optional[bytes] = None
        best_len = 0
        run_start = mem_addrs[0]
        prev = mem_addrs[0]
        for addr in mem_addrs[1:]:
            if addr != prev + 1:
                # End of a run, evaluate it.
                length = prev - run_start + 1
                if length >= best_len:
                    try:
                        data = state.solver.eval(
                            state.memory.load(run_start, length), cast_to=bytes
                        )
                    except Exception:
                        data = b""
                    null_idx = data.find(b"\x00")
                    candidate = data[:null_idx] if null_idx >= 0 else data
                    if len(candidate) > best_len:
                        best = candidate
                        best_len = len(candidate)
                run_start = addr
            prev = addr
        # Evaluate the last run.
        length = prev - run_start + 1
        if length >= best_len:
            try:
                data = state.solver.eval(
                    state.memory.load(run_start, length), cast_to=bytes
                )
            except Exception:
                data = b""
            null_idx = data.find(b"\x00")
            candidate = data[:null_idx] if null_idx >= 0 else data
            if len(candidate) > best_len:
                best = candidate
        return best
    except Exception:
        return None


def explore(
    proj: angr.Project,
    input_setup: InputSetup,
    cfg: ExploreConfig,
) -> Optional[Solution]:
    """Run the exploration and return a *Solution* if found."""
    global _EXPLORE_TIMED_OUT
    _EXPLORE_TIMED_OUT = False

    start = time.time()
    logger.info("[+] Beginning exploration")

    state = input_setup.state
    find = cfg.find_addresses
    avoid = cfg.avoid_addresses

    if cfg.use_unicorn:
        logger.info("[+] Unicorn engine enabled")
        state.options.add(angr.options.UNICORN)
        state.options.add(angr.options.UNICORN_HANDLE_SYMBOLIC_SYSCALLS)

    simgr = proj.factory.simulation_manager(state, veritesting=cfg.veritesting)

    if cfg.max_active is not None:
        simgr.active_state_limit = cfg.max_active

    if cfg.max_depth is not None:
        simgr.use_technique(angr.exploration_techniques.LengthLimiter(cfg.max_depth, drop=True))

    # Set up a step_func callback that checks timeout and logs progress.
    step_counts: List[int] = [0]
    timed_out: List[bool] = [False]
    start_time: float = time.time()

    def _step_func(simgr_inner: Any) -> bool:
        step_counts[0] += 1
        if cfg.timeout is not None and (time.time() - start_time) > cfg.timeout:
            timed_out[0] = True
            return True  # return True to stop exploration
        if cfg.max_steps is not None and step_counts[0] >= cfg.max_steps:
            timed_out[0] = True
            return True
        if step_counts[0] % 100 == 0:
            logger.info(
                "[*] Step %d | active=%d, found=%d, deadended=%d, avoided=%d",
                step_counts[0],
                len(simgr_inner.active),
                _stash_count(simgr_inner, "found"),
                len(simgr_inner.deadended),
                _stash_count(simgr_inner, "avoided"),
            )
        return False

    try:
        explore_kwargs: dict = {}
        if find:
            explore_kwargs["find"] = find
        if avoid:
            explore_kwargs["avoid"] = avoid

        if cfg.timeout is not None:
            # Use signal-based timeout for hard kill.
            signal.signal(signal.SIGALRM, _timeout_handler)
            signal.alarm(int(cfg.timeout) + 1)

        simgr.explore(step_func=_step_func, **explore_kwargs)

    except TimeoutError:
        logger.info("[!] Exploration timed out after %.1f s", cfg.timeout)
    except KeyboardInterrupt:
        logger.info("[!] Interrupted by user")
    except Exception as e:
        logger.info("[!] Exploration error: %s", e)
    finally:
        if cfg.timeout is not None:
            signal.alarm(0)

    elapsed = (time.time() - start) * 1000.0
    found_states = list(simgr._stashes.get("found", []))
    explored_total = (
        len(simgr.active)
        + len(simgr.deadended)
        + _stash_count(simgr, "avoided")
        + len(found_states)
    )

    if not found_states:
        logger.info("[!] No solution found after %d steps", step_counts[0])
        return None

    s = found_states[0]
    find_addr = s.addr

    sol = Solution(
        find_addr=find_addr,
        active_states=len(simgr.active),
        explored_states=explored_total,
        timing_ms=elapsed,
    )

    # Extract payloads from all possible input sources.
    # Since we auto-create stdin when --argv is used, a program that reads
    # from stdin will have constrained data there; the explicitly requested
    # source may still be unconstrained filler.  We suppress extraction
    # results that are mostly control characters (solver noise).
    def _meaningful(data: bytes) -> bool:
        if len(data) < 2:
            return False
        n_printable = sum(1 for b in data if 32 <= b < 127)
        # Require at least 80 % printable bytes and at least one char
        # that is not `?` (0x3F – common solver filler).
        if n_printable < len(data) * 0.8:
            return False
        return any(32 <= b < 127 and b != 0x3F for b in data)

    if input_setup.stdin_size > 0:
        data = _extract_stdin(s, input_setup.stdin_size)
        if data is not None and _meaningful(data):
            sol.stdin = data

    if input_setup.argv_size > 0 and input_setup.argv_addr is not None:
        data = _extract_argv_from_mem(s, input_setup.argv_addr, input_setup.argv_size)
        if data is not None and _meaningful(data):
            sol.argv = data

    for sf in input_setup.files:
        data = _extract_file(s, sf)
        if data is not None and _meaningful(data):
            sol.files[sf.filename] = data

    # Fallback: if no standard source produced data, scan stack memory
    # for constrained symbolic bytes (programs that read from uninitialized
    # local buffers, e.g. char buf[64] filled by angr's symbolic memory).
    if not sol.stdin and not sol.argv and not sol.files:
        data = _extract_general(s)
        if data is not None and _meaningful(data):
            sol.generic = data

    logger.info("[+] Solution found")
    return sol


def _stash_count(simgr: angr.sim_manager.SimulationManager, name: str) -> int:
    return len(simgr._stashes.get(name, []))
