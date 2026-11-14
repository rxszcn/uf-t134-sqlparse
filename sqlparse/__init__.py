#
# Copyright (C) 2009-2020 the sqlparse authors and contributors
# <see AUTHORS file>
#
# This module is part of python-sqlparse and is released under
# the BSD License: https://opensource.org/licenses/BSD-3-Clause

"""Parse SQL statements."""

# Setup namespace
from collections.abc import Generator
from typing import IO, Any

from sqlparse import cli, engine, filters, formatter, sql, tokens

__version__ = "0.6.1"
__all__ = ["cli", "engine", "filters", "formatter", "sql", "tokens"]


def parse(
    sql: str,
    encoding: str | None = None,
    max_grouping_depth: int | object = engine.grouping._USE_DEFAULT,
    max_grouping_tokens: int | object = engine.grouping._USE_DEFAULT,
) -> tuple[sql.Statement, ...]:
    """Parse sql and return a list of statements.

    :param sql: A string containing one or more SQL statements.
    :param encoding: The encoding of the statement (optional).
    :param max_grouping_depth: Override for the grouping recursion depth
        limit (default: 100). ``None`` disables the limit.
    :param max_grouping_tokens: Override for the maximum number of tokens
        processed in a single grouping operation (default: 10000).
        ``None`` disables the limit.
    :returns: A tuple of :class:`~sqlparse.sql.Statement` instances.
    """
    return tuple(parsestream(
        sql, encoding,
        max_grouping_depth=max_grouping_depth,
        max_grouping_tokens=max_grouping_tokens))


def parsestream(
    stream: str | IO[str],
    encoding: str | None = None,
    max_grouping_depth: int | object = engine.grouping._USE_DEFAULT,
    max_grouping_tokens: int | object = engine.grouping._USE_DEFAULT,
) -> Generator[sql.Statement, None, None]:
    """Parses sql statements from file-like object.

    :param stream: A file-like object.
    :param encoding: The encoding of the stream contents (optional).
    :param max_grouping_depth: Override for the grouping recursion depth
        limit (default: 100). ``None`` disables the limit.
    :param max_grouping_tokens: Override for the maximum number of tokens
        processed in a single grouping operation (default: 10000).
        ``None`` disables the limit.
    :returns: A generator of :class:`~sqlparse.sql.Statement` instances.
    """
    stack = engine.FilterStack(
        max_grouping_depth=max_grouping_depth,
        max_grouping_tokens=max_grouping_tokens)
    stack.enable_grouping()
    return stack.run(stream, encoding)


def format(sql: str, encoding: str | None = None, **options: Any) -> str:
    """Format *sql* according to *options*.

    Available options are documented in :ref:`formatting`.

    In addition to the formatting options this function accepts the
    keyword "encoding" which determines the encoding of the statement,
    as well as "max_grouping_depth" and "max_grouping_tokens" which
    override the grouping-stage DoS protection limits.

    :returns: The formatted SQL statement as string.
    """
    max_grouping_depth = options.pop(
        'max_grouping_depth', engine.grouping._USE_DEFAULT)
    max_grouping_tokens = options.pop(
        'max_grouping_tokens', engine.grouping._USE_DEFAULT)
    stack = engine.FilterStack(
        max_grouping_depth=max_grouping_depth,
        max_grouping_tokens=max_grouping_tokens)
    options = formatter.validate_options(options)
    stack = formatter.build_filter_stack(stack, options)
    stack.postprocess.append(filters.SerializerUnicode())
    return "".join(stack.run(sql, encoding))


def split(
    sql: str, encoding: str | None = None, strip_semicolon: bool = False
) -> list[str]:
    """Split *sql* into single statements.

    :param sql: A string containing one or more SQL statements.
    :param encoding: The encoding of the statement (optional).
    :param strip_semicolon: If True, remove trailing semicolons
        (default: False).
    :returns: A list of strings.
    """
    stack = engine.FilterStack(strip_semicolon=strip_semicolon)
    return [str(stmt).strip() for stmt in stack.run(sql, encoding)]
