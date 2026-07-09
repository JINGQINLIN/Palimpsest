/**
 * @name Taint from uh_cgi_auth_check parameters
 * @kind problem
 * @id custom/r9000-auth-check-taint
 */

import cpp
import semmle.code.cpp.dataflow.new.TaintTracking

module AuthCheckTaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(Function f |
      f.hasName("uh_cgi_auth_check") and
      source.asParameter() = f.getAParameter()
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(Call c |
      c.getTarget().hasName([
        "uh_b64decode", "system", "snprintf", "strchr",
        "strlen", "strcasecmp", "strncasecmp", "strcmp",
        "config_match", "update_login", "update_login_guest",
        "cat_file", "strstr", "uh_http_sendf"
      ]) and
      sink.asExpr() = c.getAnArgument()
    )
  }
}

module AuthCheckFlow = TaintTracking::Global<AuthCheckTaintConfig>;

from DataFlow::Node source, DataFlow::Node sink
where AuthCheckFlow::flow(source, sink)
select sink, "Taint from parameter " + source.toString() + " reaches $@", sink, sink.toString()