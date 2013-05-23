%{
/*
 * Tokenizer for parsing the match member of a v1+ sl_notify struct
 *
 * Copyright (C) 2009 IBM Corporation
 *
 * @author Jim Keniston <jkenisto@us.ibm.com>
 */

#include "v29_notify_gram.h"
%}

%option noyywrap

%%

[Aa][Nn][Dd]		{ return KW_AND; }
[Oo][Rr]		{ return KW_OR; }
[Tt][Yy][Pp][Ee]	{ return KW_TYPE; }
[Ss][Ee][Vv][Ee][Rr][Ii][Tt][Yy]	{ return KW_SEVERITY; }
[Ss][Ee][Rr][Vv][Ii][Cc][Ee][Aa][Bb][Ll][Ee]	{ return KW_SERVICEABLE; }

\$[Bb][Aa][Ss][Ii][Cc]	{ return KW_BASIC; }
\$[Oo][Ss]		{ return KW_OS; }
\$[Rr][Tt][Aa][Ss]	{ return KW_RTAS; }
\$[Bb][Mm][Cc]		{ return KW_BMC; }
\$[Ee][Nn][Cc][Ll][Oo][Ss][Uu][Rr][Ee]	{ return KW_ENCLOSURE; }

\$[Ff][Aa][Tt][Aa][Ll]	{ return KW_FATAL; }
\$[Ee][Rr][Rr][Oo][Rr]	{ return KW_ERROR; }
\$[Ee][Rr][Rr][Oo][Rr]_[Ll][Oo][Cc][Aa][Ll]	{ return KW_ERROR_LOCAL; }
\$[Ww][Aa][Rr][Nn][Ii][Nn][Gg]	{ return KW_WARNING; }
\$[Ee][Vv][Ee][Nn][Tt]	{ return KW_EVENT; }
\$[Ii][Nn][Ff][Oo]	{ return KW_INFO; }
\$[Dd][Ee][Bb][Uu][Gg]	{ return KW_DEBUG; }

[0-9]+	{
		v29nfy_lval.ival = strtoul((char *)yytext, (char **)NULL, 10);
		return TK_INT;
	}

"=="	{ return TK_EQ; }
"="	{ return TK_EQ; }
"!="	{ return TK_NE; }
"<>"	{ return TK_NE; }
">="	{ return TK_GE; }
">"	{ return TK_GT; }

[ \t\r] ;	/* Skip white space. */

.	{ return yytext[0];	/* Pass through any other characters. */ }

%%

static YY_BUFFER_STATE buffer_state;

void
v29nfy_lex_init(const char *parse_me)
{
	buffer_state = yy_scan_string(parse_me);
}

void
v29nfy_lex_fini(void)
{
	yy_delete_buffer(buffer_state);
}
