from __future__ import annotations

import unittest

from pipeline.stages.ghidra import FunctionContext
from pipeline.stages.reconstruct._llm import (
    _filter_pcode,
    _needs_pcode,
    _validate_struct_updates,
)
from pipeline.stages.reconstruct.evidence import (
    build_access_evidence_index,
    format_evidence_bundle,
)


class AccessEvidenceTests(unittest.TestCase):
    def test_groups_bare_offsets_and_call_argument_positions(self) -> None:
        contexts = {
            "00408a08": FunctionContext(
                address="00408a08",
                ghidra_name="reject_set_connection_type",
                code=(
                    "void reject_set_connection_type(int ctx_ptr) {\n"
                    "  char name_value_list[100];\n"
                    "  ParseNameValue(*(int *)(ctx_ptr + 0x1c) + "
                    "*(int *)(ctx_ptr + 0x30), *(undefined4 *)(ctx_ptr + 0x2c), "
                    "name_value_list);\n"
                    "}\n"
                ),
            ),
            "004092cc": FunctionContext(
                address="004092cc",
                ghidra_name="handle_add_port_mapping",
                code=(
                    "void handle_add_port_mapping(int param_1) {\n"
                    "  ParseNameValue(*(int *)(param_1 + 0x1c) + "
                    "*(int *)(param_1 + 0x30), *(undefined4 *)(param_1 + 0x2c), "
                    "soap_params);\n"
                    "}\n"
                ),
            ),
            "0040ab7c": FunctionContext(
                address="0040ab7c",
                ghidra_name="ParseNameValue",
                code="void ParseNameValue(char *xml_buf, int xml_len, struct name_value_list *nv_list) {\n}\n",
            ),
        }

        index = build_access_evidence_index(contexts)
        bundle = format_evidence_bundle(index, contexts, "00408a08")

        self.assertIn("Current object `ctx_ptr`", bundle)
        self.assertIn("+0x1c", bundle)
        self.assertIn("+0x2c", bundle)
        self.assertIn("+0x30", bundle)
        self.assertIn("ParseNameValue arg0/3", bundle)
        self.assertIn("ParseNameValue arg1/3", bundle)
        self.assertIn("handle_add_port_mapping", bundle)
        self.assertIn("void ParseNameValue(char *xml_buf, int xml_len", bundle)
        self.assertIn("context around line 3", bundle)
        self.assertIn("L1: void reject_set_connection_type", bundle)

    def test_pcode_filter_is_conservative_excerpt(self) -> None:
        raw_c = "ParseNameValue(*(int *)(ctx_ptr + 0x1c), *(undefined4 *)(ctx_ptr + 0x2c), out);"
        pcode = "\n".join(
            [
                "00408a24: (unique, 0x10000026, 4) = INT_ADD((register,0x10,4),(const,0x1c,4))",
                "00408a28: (register, 0x8, 4) = LOAD((const,0x1a1,4),(unique,0x200,4))",
                "00408a40: CALL((ram,0x40ab7c,4),(register,0x10,4),(register,0x14,4))",
            ]
        )

        self.assertTrue(_needs_pcode(raw_c))
        filtered = _filter_pcode(pcode, raw_c_code=raw_c)
        self.assertIn("INT_ADD", filtered)
        self.assertIn("LOAD", filtered)
        self.assertIn("CALL", filtered)
        self.assertNotIn("register |", filtered)

    def test_control_flow_destination_is_given_to_llm_as_evidence(self) -> None:
        contexts = {
            "1": FunctionContext(address="1", ghidra_name="f", code=(
                "void f(int cond) {\n"
                "  if (cond) { goto LAB_1; }\n"
                "  work(*(int *)(cond + 4));\n"
                "LAB_1:\n"
                "  cleanup();\n"
                "  return;\n"
                "}\n"
            )),
        }
        bundle = format_evidence_bundle(build_access_evidence_index(contexts), contexts, "1")
        self.assertIn("Control-flow destination evidence", bundle)
        self.assertIn("LAB_1 destination", bundle)
        self.assertIn("cleanup();", bundle)

    def test_control_flow_evidence_is_available_without_memory_accesses(self) -> None:
        contexts = {
            "1": FunctionContext(address="1", ghidra_name="f", code=(
                "void f(int cond) {\n"
                "  if (cond) goto LAB_1;\n"
                "  return;\n"
                "LAB_1:\n"
                "  cleanup();\n"
                "  return;\n"
                "}\n"
            )),
        }
        bundle = format_evidence_bundle(build_access_evidence_index(contexts), contexts, "1")
        self.assertIn("Control-flow destination evidence", bundle)
        self.assertIn("cleanup();", bundle)

    def test_same_placeholder_does_not_outrank_shared_call_argument(self) -> None:
        contexts = {
            "1": FunctionContext(address="1", ghidra_name="target", code=
                "void target(int param_1) { parse(*(int *)(param_1 + 28), *(int *)(param_1 + 44)); }"),
            "2": FunctionContext(address="2", ghidra_name="unrelated", code=
                "void unrelated(int param_1) { save(*(int *)(param_1 + 28), *(int *)(param_1 + 44)); }"),
            "3": FunctionContext(address="3", ghidra_name="sibling", code=
                "void sibling(int other) { parse(*(int *)(other + 28), *(int *)(other + 44)); }"),
        }
        index = build_access_evidence_index(contexts)
        bundle = format_evidence_bundle(index, contexts, "1", max_related=1)
        self.assertIn("sibling", bundle)
        self.assertNotIn("unrelated", bundle)
        self.assertIn("identity unproven", bundle)

    def test_repeated_offset_contract_is_surfaced_for_struct_recovery(self) -> None:
        contexts = {
            str(i): FunctionContext(
                address=str(i),
                ghidra_name=f"handler_{i}",
                code=(
                    f"void handler_{i}(int p) {{\n"
                    "  parse(*(int *)(p + 28), *(undefined4 *)(p + 44));\n"
                    "  check(*(int *)(p + 48));\n"
                    "}\n"
                ),
            )
            for i in range(1, 4)
        }
        bundle = format_evidence_bundle(build_access_evidence_index(contexts), contexts, "1")
        self.assertIn("repeated cross-function access contract", bundle)
        self.assertIn("+0x1c", bundle)
        self.assertIn("at least three functions", bundle)

    def test_index_units_and_pointer_width_are_not_invented(self) -> None:
        contexts = {"1": FunctionContext(address="1", ghidra_name="f", code=
            "int f(int *words, int p) { use(words[0x10]); return *(char **)(p + 28); }")}
        index = build_access_evidence_index(contexts)
        facts = [fact for obj in index.by_address["1"] for fact in obj.facts]
        self.assertEqual(len(facts), 2)
        words = next(f for f in facts if f.base == "words")
        self.assertEqual((words.access_kind, words.size, words.byte_offset), ("index", 4, 64))
        self.assertEqual(next(f for f in facts if f.base == "p").size, 0)
        bundle = format_evidence_bundle(index, contexts, "1")
        self.assertIn("byte offset unverified", bundle)
        self.assertNotIn("size_or_count_argument_candidate", bundle)

    def test_decimal_index_writer_is_retrieved_among_repeated_consumers(self) -> None:
        contexts = {
            str(i): FunctionContext(address=str(i), ghidra_name=f"consume_{i}", code=
                f"void consume_{i}(int p) {{ parse(*(int *)(p + 28), *(int *)(p + 44)); }}")
            for i in range(1, 7)
        }
        contexts["9"] = FunctionContext(address="9", ghidra_name="writer", code=
            "void writer(int *p) {\n void *buf = realloc((void *)p[7], 100);\n p[7] = (int)buf;\n p[11] = 80;\n }")
        index = build_access_evidence_index(contexts)
        bundle = format_evidence_bundle(index, contexts, "1", max_related=3)
        self.assertIn("writer", bundle)
        self.assertIn("realloc", bundle)
        self.assertIn("index 7 -> byte +0x1c", bundle)
        self.assertIn("p[11] = 80", bundle)
        self.assertNotIn("consume_4", bundle)

    def test_unknown_pointee_is_not_scaled_and_array_declarations_are_not_accesses(self) -> None:
        contexts = {"1": FunctionContext(address="1", ghidra_name="f", code=
            "void f(struct unknown *p, char **q) { int words[20]; use(p[7], q[7], words[7]); }")}
        index = build_access_evidence_index(contexts)
        facts = [f for obj in index.by_address["1"] for f in obj.facts]
        self.assertEqual(len(facts), 3)
        self.assertEqual(next(f for f in facts if f.base == "words").byte_offset, 28)
        self.assertTrue(all(f.byte_offset is None for f in facts if f.base in ("p", "q")))

    def test_direct_stack_object_argument_includes_callee_use(self) -> None:
        contexts = {
            "1": FunctionContext(address="1", ghidra_name="f", code=
                "void f(int value) { int data[3]; data[0] = value; consume(data); }"),
            "2": FunctionContext(address="2", ghidra_name="consume", code=
                "void consume(int *p) { p[2] = p[0] + p[1]; }"),
        }
        bundle = format_evidence_bundle(build_access_evidence_index(contexts), contexts, "1")
        self.assertIn("p[2] = p[0] + p[1]", bundle)

    def test_callee_body_and_nearby_use_are_provided_with_bounded_budget(self) -> None:
        contexts = {
            "1": FunctionContext(address="1", ghidra_name="target", code=
                "void target(int p) { parse(*(int *)(p + 28), *(int *)(p + 44)); }"),
            "2": FunctionContext(address="2", ghidra_name="sibling", code=
                "void sibling(int p) {\n prepare(p);\n parse(*(int *)(p + 28), *(int *)(p + 44));\n release(p);\n}"),
            "3": FunctionContext(address="3", ghidra_name="parse", code=
                "void parse(char *buf, int length) {\n consume(buf, length);\n" + " work();\n" * 1000 + "}"),
        }
        index = build_access_evidence_index(contexts)
        bundle = format_evidence_bundle(index, contexts, "1")
        self.assertIn("prepare(p)", bundle)
        self.assertIn("release(p)", bundle)
        self.assertIn("consume(buf, length)", bundle)
        self.assertLess(len(bundle), 12100)

    def test_struct_updates_are_not_rejected_by_unbound_pcode_offsets(self) -> None:
        updates = [
            {
                "name": "request_context",
                "size": 52,
                "fields": [
                    {"offset": 28, "name": "field_1c", "type": "char *", "size": 4},
                    {"offset": 44, "name": "field_2c", "type": "int", "size": 4},
                    {"offset": 48, "name": "field_30", "type": "int", "size": 4},
                ],
            }
        ]
        pcode = "00408a28: (register, 0x8, 4) = LOAD((const,0x1a1,4),(unique,0x200,4))"

        self.assertEqual(_validate_struct_updates(updates, pcode), updates)


if __name__ == "__main__":
    unittest.main()
