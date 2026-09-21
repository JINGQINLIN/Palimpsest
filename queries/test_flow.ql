/**
 * @name Command Injection with dangerous command
 * @description High sensitivity and precision version of command injection detection
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision high
 * @id python/command-injection-high-precision
 * @tags security
 *       external/cwe/cwe-078
 */


 import cpp
 import semmle.code.cpp.ir.dataflow.DataFlow
 import semmle.code.cpp.ir.dataflow.TaintTracking
 
 
 module MyFlowConfig implements DataFlow::ConfigSig {

  predicate isSource(DataFlow::Node src) {
    (
      src.asExpr().(Call).getTarget().hasName("uh_cgi_auth_check")
      or
      src.asParameter().getFunction().hasName("uh_cgi_auth_check")
   )
}

  predicate isSink(DataFlow::Node snk) {
    exists(Call c|
      c.getTarget().getName() = "system" and
      c.getAnArgument() = snk.asExpr()
  )
  }

  predicate isAdditionalFlowStep(DataFlow::Node prev, DataFlow::Node next) {
    exists(Call c |
        (
            c.toString() = "call to uh_b64decode" and
            c.getAnArgument() = prev.asExpr() and
            c.getAnArgument() = next.asExpr()
        )
    )
    or
    exists(Call c |
        (
            c.toString() = "call to snprintf" and
            c.getAnArgument() = prev.asExpr() and
            c.getAnArgument() = next.asExpr()
        )
    )
    or
    exists(Call c |
        (
            c.toString() = "call to strchr" and
            c.getAnArgument() = prev.asExpr() and (
              c = next.asExpr() or
              c.getAnArgument() = next.asExpr()
            )
        )
    )
    or
    exists(FieldAccess fa |
    (next.asExpr() = fa or
    next.asIndirectExpr() = fa)
    and
    (prev.asIndirectExpr() = fa.getQualifier() or prev.asExpr() = fa.getQualifier())
  )
  }
}
 /** Tracks flow of unvalidated user input that is used in Runtime.Exec */
 module MyFlow = TaintTracking::Global<MyFlowConfig>;
 
 import MyFlow::PathGraph
  
 from MyFlow::PathNode source, MyFlow::PathNode sink
 //, DataFlow::Node sourceCmd,   DataFlow::Node sinkCmd
 where  MyFlow::flowPath(source, sink)
 // where mycallIsTaintedByUserInputAndDangerousCommand(source, sink, sourceCmd, sinkCmd)
 select sink, source, sink,
 "Command injection vulnerability: dangerous command '$@' with argument from untrusted input",
 source.getNode(), source.toString(), sink.toString(), sink.getNode().asExpr().toString()