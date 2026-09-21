from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch, Mock

from pipeline.registry.coherence import check_field_coherence
from pipeline.registry.structs import (
    StructRegistry,
    normalize_fields,
    normalize_offset_field_names,
)
from pipeline.stages.reconstruct._apply import _apply_struct_updates
from pipeline.stages.reconstruct.orchestrate import process_function
from pipeline.c_source import (
    apply_local_renames,
    reconstruction_errors,
)
from pipeline.llm import TokenUsage
from pipeline.prompts import PromptManager
from pipeline.stages.reconstruct._llm import _run_naming_phase


class StructRegistryTests(unittest.TestCase):
    def test_naming_phase_accepts_table_without_regenerated_c(self) -> None:
        llm = Mock()
        llm.complete.return_value = (
            '<naming_map>param_1 -> length | evidence: count</naming_map><registry_updates>[]</registry_updates>',
            TokenUsage(),
        )
        named, mapping, updates = _run_naming_phase(
            prompts=PromptManager(), llm=llm, usage=TokenUsage(), binary_name="test", address=1,
            ghidra_name="f", naming_context="", structured="void f(int param_1) { use(param_1); }",
            known_symbols={}, unknown_symbols=[], registry=None, language_directive="",
        )
        self.assertEqual(named, "void f(int length) { use(length); }")
        self.assertIn("param_1 -> length", mapping)
        self.assertEqual(updates, [])

    def test_local_naming_changes_declaration_and_uses_without_touching_fields_or_literals(self) -> None:
        code = '''void f(int param_1) {
  struct state local_20;
  struct node *p;
  use(&local_20, param_1);
  /* local_20 */
  print("local_20", p->local_20);
}'''
        named, log = apply_local_renames(code, "local_20 -> state_value | evidence: passed to use\nparam_1 -> length | evidence: size")
        self.assertIn("struct state state_value;", named)
        self.assertIn("use(&state_value, length)", named)
        self.assertIn('print("local_20", p->local_20)', named)
        self.assertIn("/* local_20 */", named)
        self.assertIn("int length", named)
        self.assertNotIn("skipped", log)

    def test_local_naming_rejects_collisions_and_nonlocal_identifiers(self) -> None:
        code = "void f(int a, int b) { use(a, b); }"
        named, log = apply_local_renames(code, "a -> b\nb -> while\nuse -> danger")
        self.assertEqual(named, code)
        self.assertEqual(log.count("skipped"), 3)

    def test_inline_array_and_delimiter_regressions_are_reported(self) -> None:
        raw = 'void f(void) { char buf[32]; fill(buf, 32); if (ready()) { use(buf); } }'
        changed = 'void f(void) { char *buf; fill(&buf, 32); if ((ready()) { use(buf); } }'
        self.assertEqual(len(reconstruction_errors(raw, changed)), 2)
        self.assertEqual(reconstruction_errors(raw, raw + '\n/* char *buf; ( */'), [])
        self.assertEqual(reconstruction_errors(raw, raw.replace('ready()', 'test("(")')), [])

    def test_registry_conflict_is_repaired_before_naming_with_one_shared_budget(self) -> None:
        raw = "void f(int p) { consume(*(int *)(p + 4)); }"
        candidate = "void f(struct ctx *p) { consume(p->new_field); }"
        extra = {"offset": 4, "name": "new_field", "type": "int", "size": 4}
        conflicting = [{"name": "ctx", "fields": [
            {"offset": 0, "name": "state", "type": "void *", "size": 4}, extra,
        ]}]
        for repaired in (True, False):
            with self.subTest(repaired=repaired), TemporaryDirectory() as tmp:
                reg = StructRegistry(Path(tmp) / "structs.sqlite3")
                reg.update(name="ctx", fields=[
                    {"offset": 0, "name": "state", "type": "int", "size": 4},
                ])
                repairs = [{"name": "ctx", "fields": [extra]}] if repaired else conflicting
                prefix = "pipeline.stages.reconstruct.orchestrate."
                try:
                    with patch(prefix + "_run_structure_phase", return_value=(candidate, conflicting, "")), \
                         patch(prefix + "_run_structure_coherence_repair", return_value=(candidate, repairs)) as repair, \
                         patch(prefix + "_run_naming_phase", side_effect=lambda **kw: (kw["structured"], "", [])) as naming:
                        result = process_function(
                            binary_name="test", address=1, ghidra_name="f", raw_decompile=raw,
                            known_symbols={}, unknown_symbols=[], registry=None, struct_registry=reg,
                            llm=None, structure_context="", naming_context="",
                        )
                    expected = candidate if repaired else raw
                    self.assertEqual(result.structured, expected)
                    self.assertEqual(naming.call_args.kwargs["structured"], expected)
                    self.assertEqual(repair.call_count, 1)
                    self.assertEqual(reg.lookup("ctx")["fields"][0]["type"], "int")
                    self.assertTrue(check_field_coherence(result.structured, reg.get_all()).ok)
                finally:
                    reg.close()

    def test_normalize_offset_placeholder_names(self) -> None:
        self.assertEqual(
            normalize_fields(
                [{"offset": 28, "name": "field_0x1c", "type": "int", "size": 4}]
            ),
            [{"offset": 28, "name": "field_1c", "type": "int", "size": 4}],
        )
        self.assertEqual(
            normalize_offset_field_names("ctx->field_0x1c + ctx->field_0X30"),
            "ctx->field_1c + ctx->field_30",
        )

    def test_struct_registry_merges_non_overlapping_fields(self) -> None:
        with TemporaryDirectory() as tmp:
            reg = StructRegistry(Path(tmp) / "structs.sqlite3")
            try:
                self.assertEqual(
                    reg.update(
                        name="upnp_http",
                        fields=[
                            {"offset": 100, "name": "res_buf", "type": "char *", "size": 4},
                            {"offset": 104, "name": "res_len", "type": "int", "size": 4},
                        ],
                        size=116,
                        confidence="high",
                    ),
                    "inserted",
                )
                self.assertEqual(
                    reg.update(
                        name="upnp_http",
                        fields=[
                            {"offset": 28, "name": "field_1c", "type": "int", "size": 4},
                            {"offset": 44, "name": "field_2c", "type": "undefined4", "size": 4},
                            {"offset": 48, "name": "field_30", "type": "int", "size": 4},
                        ],
                        size=116,
                        confidence="high",
                    ),
                    "merged",
                )

                fields = {f["offset"]: f["name"] for f in reg.lookup("upnp_http")["fields"]}
                self.assertEqual(fields[28], "field_1c")
                self.assertEqual(fields[44], "field_2c")
                self.assertEqual(fields[48], "field_30")
                self.assertEqual(fields[100], "res_buf")
                self.assertEqual(fields[104], "res_len")
                self.assertEqual(reg.get_conflict_count(), 0)
            finally:
                reg.close()

    def test_struct_registry_rejects_same_offset_mismatch(self) -> None:
        with TemporaryDirectory() as tmp:
            reg = StructRegistry(Path(tmp) / "structs.sqlite3")
            try:
                reg.update(
                    name="ctx",
                    fields=[{"offset": 28, "name": "field_1c", "type": "int", "size": 4}],
                    size=32,
                    confidence="medium",
                )
                self.assertEqual(
                    reg.update(
                        name="ctx",
                        fields=[{"offset": 28, "name": "data_ptr", "type": "char *", "size": 4}],
                        size=32,
                        confidence="high",
                    ),
                    "conflict",
                )
                self.assertEqual(reg.lookup("ctx")["fields"][0]["name"], "field_1c")
                self.assertEqual(reg.get_conflict_count(), 1)
            finally:
                reg.close()

    def test_struct_registry_upgrades_placeholder_name_with_same_layout(self) -> None:
        with TemporaryDirectory() as tmp:
            reg = StructRegistry(Path(tmp) / "structs.sqlite3")
            try:
                self.assertEqual(
                    reg.update(
                        name="parser_data",
                        fields=[{"offset": 0x44, "name": "field_44", "type": "void *", "size": 4}],
                        size=0x48,
                        confidence="medium",
                    ),
                    "inserted",
                )
                self.assertEqual(
                    reg.update(
                        name="parser_data",
                        fields=[{"offset": 0x44, "name": "port_listing", "type": "void *", "size": 4}],
                        size=0x48,
                        confidence="high",
                    ),
                    "merged",
                )
                self.assertEqual(reg.lookup("parser_data")["fields"][0]["name"], "port_listing")
            finally:
                reg.close()

    def test_apply_struct_updates_returns_only_applied_entries(self) -> None:
        with TemporaryDirectory() as tmp:
            reg = StructRegistry(Path(tmp) / "structs.sqlite3")
            try:
                reg.update(
                    name="ctx",
                    fields=[{"offset": 0, "name": "state", "type": "int", "size": 4}],
                    size=4,
                    confidence="medium",
                )
                applied = _apply_struct_updates(
                    reg,
                    [
                        {
                            "name": "ctx",
                            "fields": [{"offset": 0, "name": "fd", "type": "int", "size": 4}],
                            "size": 4,
                            "confidence": "high",
                        }
                    ],
                    source_file="binary",
                )
                self.assertEqual(applied, [])
                self.assertEqual(reg.get_conflict_count(), 1)
            finally:
                reg.close()

    def test_coherence_extra_structs_extend_existing_fields(self) -> None:
        structs = {
            "upnp_http": {
                "fields": [
                    {"offset": 100, "name": "res_buf", "type": "char *", "size": 4},
                    {"offset": 104, "name": "res_len", "type": "int", "size": 4},
                ]
            }
        }
        code = """
        void f(struct upnp_http *http) {
          use(http->field_1c + http->res_len);
        }
        """
        extra = [
            {
                "name": "upnp_http",
                "fields": [{"offset": 28, "name": "field_0x1c", "type": "int", "size": 4}],
            }
        ]
        self.assertTrue(check_field_coherence(code, structs, extra_structs=extra).ok)


if __name__ == "__main__":
    unittest.main()
