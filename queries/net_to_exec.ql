/**
 * @name Network input to command execution
 * @description Taint-tracking from a received network buffer (read/recv*) to a
 *              command-execution sink (system/popen/exec*). Used to A/B the
 *              reconstruction: the is_guest_client chain only connects when the
 *              DHCP packet keeps its struct-pointer type across handler calls.
 * @kind path-problem
 * @id semant/net-to-exec
 * @problem.severity warning
 */

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking
import semmle.code.cpp.dataflow.new.DataFlow

predicate isExecFunction(Function f) {
  f.hasName([
      "system", "___system", "popen", "execl", "execlp", "execle",
      "execv", "execvp", "execve", "posix_spawn", "posix_spawnp",
      "ExecShell", "CsteSystem", "doSystemCmd"
    ])
}

predicate isNetRecv(Function f) {
  f.hasName(["read", "recv", "recvfrom", "recvmsg"])
}

module NetToExecConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // the buffer filled by read()/recv*(): the received packet bytes.
    // NOTE: end-to-end flow to popen does not connect out-of-the-box because
    // CodeQL C/C++ taint needs extra indirection + sprintf modeling for this
    // firmware pattern; see packet_to_exec.ql for the structural A/B instead.
    exists(FunctionCall fc |
      isNetRecv(fc.getTarget()) and
      source.asDefiningArgument() = fc.getArgument(1)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    // the command string handed to a command-exec function
    exists(FunctionCall fc |
      isExecFunction(fc.getTarget()) and
      sink.asExpr() = fc.getArgument(0)
    )
  }
}

module NetToExec = TaintTracking::Global<NetToExecConfig>;

import NetToExec::PathGraph

from NetToExec::PathNode source, NetToExec::PathNode sink
where NetToExec::flowPath(source, sink)
select sink.getNode(), source, sink, "Network input reaches command execution."
