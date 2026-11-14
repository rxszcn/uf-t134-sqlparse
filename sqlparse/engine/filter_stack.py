#
# Copyright (C) 2009-2020 the sqlparse authors and contributors
# <see AUTHORS file>
#
# This module is part of python-sqlparse and is released under
# the BSD License: https://opensource.org/licenses/BSD-3-Clause

"""filter"""

from sqlparse import lexer
from sqlparse.engine import grouping
from sqlparse.engine.statement_splitter import StatementSplitter
from sqlparse.exceptions import SQLParseError
from sqlparse.filters import StripTrailingSemicolonFilter


class FilterStack:
    def __init__(self, strip_semicolon=False,
                 max_grouping_depth=grouping._USE_DEFAULT,
                 max_grouping_tokens=grouping._USE_DEFAULT):
        self.preprocess = []
        self.stmtprocess = []
        self.postprocess = []
        self._grouping = False
        # Validate eagerly so a misconfigured caller fails at stack
        # construction rather than halfway through processing a stream.
        self.max_grouping_depth = grouping._resolve_limit(
            'max_grouping_depth', max_grouping_depth,
            grouping.MAX_GROUPING_DEPTH)
        self.max_grouping_tokens = grouping._resolve_limit(
            'max_grouping_tokens', max_grouping_tokens,
            grouping.MAX_GROUPING_TOKENS)
        if strip_semicolon:
            self.stmtprocess.append(StripTrailingSemicolonFilter())

    def enable_grouping(self):
        self._grouping = True

    def run(self, sql, encoding=None):
        try:
            stream = lexer.tokenize(sql, encoding)
            # Process token stream
            for filter_ in self.preprocess:
                stream = filter_.process(stream)

            stream = StatementSplitter().process(stream)

            # Output: Stream processed Statements
            for stmt in stream:
                if self._grouping:
                    stmt = grouping.group(
                        stmt,
                        max_grouping_depth=self.max_grouping_depth,
                        max_grouping_tokens=self.max_grouping_tokens)

                for filter_ in self.stmtprocess:
                    filter_.process(stmt)

                for filter_ in self.postprocess:
                    stmt = filter_.process(stmt)

                yield stmt
        except RecursionError as err:
            raise SQLParseError('Maximum recursion depth exceeded') from err
