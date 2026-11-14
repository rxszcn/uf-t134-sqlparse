"""Tests for the configurable grouping-limit parameters.

The grouping-stage DoS guards (``MAX_GROUPING_DEPTH`` /
``MAX_GROUPING_TOKENS``) can be overridden per call through the public
entry points (``parse``, ``parsestream``, ``format``) and the
``FilterStack``.  When the parameters are omitted the built-in defaults
apply unchanged, so the protection tests in ``test_dos_prevention`` keep
passing verbatim.
"""

import pytest

import sqlparse
from sqlparse.engine import grouping
from sqlparse.engine.filter_stack import FilterStack
from sqlparse.exceptions import SQLParseError


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------

def wide_select(n_columns):
    """A single statement with more than *n_columns* top-level identifiers."""
    columns = ', '.join(f'col{i}' for i in range(n_columns))
    return f'SELECT {columns} FROM table1'


def tuple_in_select(n_tuples):
    sql = (
        'SELECT "t"."a", "t"."b" FROM "t" '
        'WHERE ("t"."a", "t"."b") IN ('
    )
    sql += ', '.join(f'(1, {i})' for i in range(1, n_tuples + 1))
    return sql + ')'


def nested_parens(depth):
    return 'SELECT ' + '(' * depth + '1' + ')' * depth


# A payload that exceeds the default token limit (10_000) and one that
# exceeds the default depth limit (100).
OVER_TOKENS_SQL = wide_select(12_000)
OVER_DEPTH_SQL = nested_parens(200)


def _structure(tlist, depth=0):
    """Return a hashable structural description of a grouping tree."""
    node = (type(tlist).__name__,)
    children = ()
    if tlist.is_group:
        children = tuple(_structure(token, depth + 1)
                         for token in tlist.tokens)
    return node + children


# ---------------------------------------------------------------------------
# Default behavior is unchanged (parameters omitted)
# ---------------------------------------------------------------------------

class TestDefaultProtectionUnchanged:
    def test_parse_omitting_params_keeps_token_guard(self):
        with pytest.raises(SQLParseError,
                           match='Maximum number of tokens exceeded '
                                 r'\(10000\)'):
            sqlparse.parse(OVER_TOKENS_SQL)

    def test_parse_omitting_params_keeps_depth_guard(self):
        with pytest.raises(SQLParseError,
                           match='Maximum grouping depth exceeded '
                                 r'\(100\)'):
            sqlparse.parse(OVER_DEPTH_SQL)

    def test_format_omitting_params_keeps_guards(self):
        with pytest.raises(SQLParseError,
                           match='Maximum number of tokens exceeded'):
            sqlparse.format(OVER_TOKENS_SQL, reindent=True)

    def test_filter_stack_omitting_params_keeps_guards(self):
        stack = FilterStack()
        stack.enable_grouping()
        with pytest.raises(SQLParseError,
                           match='Maximum number of tokens exceeded'):
            list(stack.run(OVER_TOKENS_SQL))


# ---------------------------------------------------------------------------
# Raising the limits lets legitimate large statements through
# ---------------------------------------------------------------------------

class TestRaisedLimits:
    def test_raised_token_limit_parses(self):
        stmts = sqlparse.parse(OVER_TOKENS_SQL, max_grouping_tokens=50_000)
        assert len(stmts) == 1
        # The parsed statement flattens back to the exact input text.
        assert str(stmts[0]) == OVER_TOKENS_SQL

    def test_raised_depth_limit_parses(self):
        stmts = sqlparse.parse(OVER_DEPTH_SQL, max_grouping_depth=300)
        assert len(stmts) == 1
        assert str(stmts[0]) == OVER_DEPTH_SQL

    def test_raised_limits_through_format(self):
        result = sqlparse.format(
            OVER_TOKENS_SQL, reindent=True, max_grouping_tokens=50_000)
        assert 'col11999' in result

    def test_raised_limits_through_parsestream(self):
        gen = sqlparse.parsestream(OVER_TOKENS_SQL,
                                  max_grouping_tokens=50_000)
        stmts = list(gen)
        assert str(stmts[0]) == OVER_TOKENS_SQL

    def test_raised_limits_through_filter_stack(self):
        stack = FilterStack(max_grouping_tokens=50_000,
                            max_grouping_depth=300)
        stack.enable_grouping()
        stmts = list(stack.run(OVER_TOKENS_SQL))
        assert str(stmts[0]) == OVER_TOKENS_SQL

    def test_limit_can_be_tightened_below_default(self):
        # A caller may also lower the limits; error text must echo the
        # caller-supplied value rather than the module default.
        sql = wide_select(500)
        with pytest.raises(SQLParseError,
                           match=r'Maximum number of tokens exceeded \(100\)'):
            sqlparse.parse(sql, max_grouping_tokens=100)

    def test_depth_limit_can_be_tightened_below_default(self):
        with pytest.raises(SQLParseError,
                           match=r'Maximum grouping depth exceeded \(10\)'):
            sqlparse.parse(nested_parens(50), max_grouping_depth=10)


# ---------------------------------------------------------------------------
# Disabling the limits with None
# ---------------------------------------------------------------------------

class TestDisabledLimits:
    def test_none_disables_token_limit(self):
        stmts = sqlparse.parse(OVER_TOKENS_SQL, max_grouping_tokens=None)
        assert str(stmts[0]) == OVER_TOKENS_SQL

    def test_none_disables_depth_limit(self):
        stmts = sqlparse.parse(OVER_DEPTH_SQL, max_grouping_depth=None)
        assert str(stmts[0]) == OVER_DEPTH_SQL

    def test_none_on_both_limits(self):
        stmts = sqlparse.parse(
            OVER_TOKENS_SQL,
            max_grouping_depth=None,
            max_grouping_tokens=None)
        assert str(stmts[0]) == OVER_TOKENS_SQL


# ---------------------------------------------------------------------------
# Parameter-form matrix: every supported channel must produce the same tree
# ---------------------------------------------------------------------------

class TestParameterFormEquivalence:
    def test_all_channels_build_identical_grouping_tree(self):
        sql_text = tuple_in_select(2_000)

        via_parse = sqlparse.parse(
            sql_text, max_grouping_tokens=50_000,
            max_grouping_depth=300)[0]
        via_parsestream = list(sqlparse.parsestream(
            sql_text, max_grouping_tokens=50_000,
            max_grouping_depth=300))[0]
        via_format = sqlparse.parse(
            sql_text, max_grouping_tokens=50_000)[0]

        stack = FilterStack(max_grouping_tokens=50_000,
                            max_grouping_depth=300)
        stack.enable_grouping()
        via_stack = list(stack.run(sql_text))[0]

        expected = _structure(via_parse)
        assert _structure(via_parsestream) == expected
        assert _structure(via_format) == expected
        assert _structure(via_stack) == expected
        # Every channel round-trips the original text exactly.
        for stmt in (via_parse, via_parsestream, via_format, via_stack):
            assert str(stmt) == sql_text

    def test_grouping_engine_accepts_params_directly(self):
        # The grouping engine itself is the last hop of the chain.
        from sqlparse import lexer
        from sqlparse.engine.statement_splitter import StatementSplitter

        stmt = next(StatementSplitter().process(
            lexer.tokenize(OVER_TOKENS_SQL)))
        grouping.group(stmt, max_grouping_tokens=50_000)
        assert str(stmt) == OVER_TOKENS_SQL

    def test_keyword_and_positional_forms_equivalent(self):
        keyword = sqlparse.parse(
            OVER_DEPTH_SQL, max_grouping_depth=300,
            max_grouping_tokens=50_000)[0]
        # parse()/parsestream() expose the limits as regular parameters,
        # so positional passing must behave identically to keywords.
        positional = sqlparse.parse(
            OVER_DEPTH_SQL, None, 300, 50_000)[0]
        assert _structure(positional) == _structure(keyword)

    def test_module_constants_still_govern_the_defaults(self):
        # The module-level constants remain the single source of the
        # default values: patching them changes parameter-less calls.
        original = grouping.MAX_GROUPING_TOKENS
        try:
            grouping.MAX_GROUPING_TOKENS = 50_000
            stmts = sqlparse.parse(OVER_TOKENS_SQL)
            assert str(stmts[0]) == OVER_TOKENS_SQL
        finally:
            grouping.MAX_GROUPING_TOKENS = original
        # Restored default guards again.
        with pytest.raises(SQLParseError,
                           match='Maximum number of tokens exceeded'):
            sqlparse.parse(OVER_TOKENS_SQL)


# ---------------------------------------------------------------------------
# Grouping tree of a large statement matches split/segmented parsing
# ---------------------------------------------------------------------------

class TestSegmentedParseConsistency:
    def test_batched_and_split_trees_match(self):
        big1 = wide_select(12_000)
        big2 = wide_select(11_000)
        batch = big1 + ';' + big2

        # Whole batch parsed in one call (the splitter segments internally).
        batched = sqlparse.parse(batch, max_grouping_tokens=50_000)
        # Explicit split followed by per-statement parsing.
        pieces = sqlparse.split(batch)
        segmented = [
            sqlparse.parse(piece, max_grouping_tokens=50_000)[0]
            for piece in pieces
        ]

        assert len(batched) == len(segmented) == 2
        for whole, part in zip(batched, segmented):
            assert _structure(whole) == _structure(part)
            assert str(whole).strip().rstrip(';') == \
                str(part).strip().rstrip(';')

    def test_raised_limit_tree_matches_unlimited_tree(self):
        # A large-but-within-raised-limit statement must group identically
        # whether the guard is raised or disabled entirely.
        sql_text = tuple_in_select(1_500)
        limited = sqlparse.parse(
            sql_text, max_grouping_tokens=50_000)[0]
        unlimited = sqlparse.parse(
            sql_text, max_grouping_tokens=None)[0]
        assert _structure(limited) == _structure(unlimited)
        assert str(limited) == str(unlimited) == sql_text


# ---------------------------------------------------------------------------
# Invalid parameter values
# ---------------------------------------------------------------------------

class TestInvalidParameters:
    @pytest.mark.parametrize('bad_value', [0, -1, -100, '100', 1.5,
                                           True, False, 1.0, object()])
    def test_invalid_max_grouping_tokens(self, bad_value):
        with pytest.raises(SQLParseError,
                           match='Invalid value for max_grouping_tokens'):
            sqlparse.parse('SELECT 1', max_grouping_tokens=bad_value)

    @pytest.mark.parametrize('bad_value', [0, -1, -100, '100', 1.5,
                                           True, False, 1.0, object()])
    def test_invalid_max_grouping_depth(self, bad_value):
        with pytest.raises(SQLParseError,
                           match='Invalid value for max_grouping_depth'):
            sqlparse.parse('SELECT 1', max_grouping_depth=bad_value)

    @pytest.mark.parametrize('bad_value', [0, -1, '50000', 2.0])
    def test_invalid_values_rejected_by_format(self, bad_value):
        with pytest.raises(SQLParseError, match='Invalid value'):
            sqlparse.format('SELECT 1', max_grouping_tokens=bad_value)

    @pytest.mark.parametrize('bad_value', [0, -1, '50000', 2.0])
    def test_invalid_values_rejected_by_filter_stack(self, bad_value):
        with pytest.raises(SQLParseError, match='Invalid value'):
            FilterStack(max_grouping_tokens=bad_value)

    def test_invalid_value_fails_before_grouping_work(self):
        # Validation happens while building the stack, so a generator-based
        # entry point must surface the error on iteration / construction
        # rather than silently producing an unguarded parse.
        with pytest.raises(SQLParseError, match='Invalid value'):
            sqlparse.parsestream('SELECT 1', max_grouping_depth=0)

    def test_none_is_a_valid_disabling_value_not_an_error(self):
        # None must not be mistaken for an invalid value.
        stmts = sqlparse.parse('SELECT 1', max_grouping_depth=None,
                               max_grouping_tokens=None)
        assert str(stmts[0]) == 'SELECT 1'
