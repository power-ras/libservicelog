%{
/**
 * @file notify_gram.y
 * @brief yacc grammar for parsing the match member of a v1+ sl_notify struct
 *
 * Copyright (C) 2009 IBM Corporation
 *
 * We accept only query expressions that can be converted to v0.2.9
 * sl_notify structs.
 *
 * Usage:
 *	v29nfy_gram_init(v1_sl_notify->match, &v29_sl_notify, &semantic_errs);
 *	if (v29nfy_parse() == 0 && semantic_errs == 0) {
 *		*v29_sl_notify_ptr is successfully populated -- the
 *		event_types, severity, and serviceable fields, anyway.
 *	}
 *	v29nfy_gram_fini();
 *
 * TODO: Serialize calls to this.
 *
 * @author Jim Keniston <jkenisto@us.ibm.com>
 */

#include "slog_internal.h"
#define EXCLUDE_SERVICELOG_COMPAT_DECLS
#include "../servicelog-1/libservicelog.h"
#include "v29_notify_gram.h"
#include <malloc.h>
#include <assert.h>

static struct v29_sl_notify *notify;
static int *semantic_errors;
extern void v29nfy_lex_init(const char *parse_me);
extern void v29nfy_lex_fini(void);
extern uint32_t convert_type_to_v29(uint32_t v1_type);

#define all_types ((1<<SL_TYPE_OS) | (1<<SL_TYPE_PPC64_RTAS) | (1<<SL_TYPE_PPC64_ENCL))

extern int yylex(void);

void
yyerror(const char *s)
{
}

static int nr_and_clauses, nr_or_clauses,
	nr_type_eq_tests, nr_type_ne_tests,
	nr_serviceability_tests, nr_severity_tests;

/* We use one or the other, not both. */
static uint64_t anded_types, ored_types;

struct parse_node {
	int nd_type;
	struct parse_node *nd_left, *nd_right;
};

static struct parse_node *
mk_parse_node(int ndty, struct parse_node *left, struct parse_node *right)
{
	struct parse_node *nd = malloc(sizeof(*nd));
	if (!nd) {
		(*semantic_errors)++;
		return NULL;
	}
	nd->nd_type = ndty;
	nd->nd_left = left;
	nd->nd_right = right;
	return nd;
}

static void
free_parse_tree(struct parse_node *root)
{
	if (!root)
		return;
	free_parse_tree(root->nd_left);
	free_parse_tree(root->nd_right);
	free(root);
}
/*
 * We've determined that the type subtree should be a set of one or more
 * type=val nodes connected by ORs.  Find that subtree.
 */
static struct parse_node *
find_type_subtree(struct parse_node *root)
{
	struct parse_node *found;
	if (!root)
		return NULL;
	if (root->nd_type  == KW_OR || root->nd_type == TK_EQ)
		return root;
	found = find_type_subtree(root->nd_left);
	if (found)
		return found;
	return find_type_subtree(root->nd_right);
}

static int
count_eq_tests_in_subtree(struct parse_node *root)
{
	if (root->nd_type == TK_EQ)
		return 1;
	else if (root->nd_type == KW_OR)
		return (count_eq_tests_in_subtree(root->nd_left)
			+ count_eq_tests_in_subtree(root->nd_right));
	(*semantic_errors)++;
	return 0;
}

/*
 * The grammar we recognize is
 *	severity_test AND serviceability_test AND type_test
 * where the order is irrelevant, any or all tests can be omitted, and
 * parenthesization is anything close to reasonable, so long as it's
 * correct.
 *
 * type_test is either a sequence of "type = value" terms strung together
 * with ORs, or a sequence of "type != value" terms strung together with
 * ANDs.  In the latter case, the "type != value" terms can be intermixed
 * with the severity_test and serviceability_test.
 *
 * All tests are represented by leaf nodes: KW_SEVERITY, KW_SERVICEABILITY,
 * KW_EQ (for type=val), or KW_NE (for type!=val).
 */
static void
validate_parse_tree(struct parse_node *root)
{
	if (!root)
		return;
	if (nr_serviceability_tests > 1 || nr_severity_tests > 1)
		goto bad;
	if (nr_type_eq_tests > 0) {
		// type=val connected by ORs
		struct parse_node *type_subtree;

		if (nr_type_ne_tests > 0)
			goto bad;
		if (nr_or_clauses != nr_type_eq_tests-1)
			goto bad;
		/* Verify that one subtree has all the ORs and type=val tests.*/
		type_subtree = find_type_subtree(root);
		if (count_eq_tests_in_subtree(type_subtree) != nr_type_ne_tests)
			goto bad;
		notify->event_types = ored_types;
	} else if (nr_type_ne_tests > 0) {
		// type!=val connected by ANDs
		if (nr_or_clauses != 0)
			goto bad;
		notify->event_types = anded_types;
	}
	free_parse_tree(root);
	return;

bad:
	(*semantic_errors)++;
	free_parse_tree(root);
}

%}

%union {
	int ival;
	struct parse_node *pnval;
}

%token <ival> KW_AND KW_OR
%token <ival> KW_TYPE KW_SEVERITY KW_SERVICEABLE
%token <ival> KW_BASIC KW_OS KW_RTAS KW_BMC KW_ENCLOSURE
%token <ival> KW_FATAL KW_ERROR KW_ERROR_LOCAL KW_WARNING KW_EVENT KW_INFO
		KW_DEBUG

%token <ival> TK_INT TK_EQ TK_NE TK_GT TK_GE

%type <ival> type_value v1_type_value severity_value
%type <pnval> qstring search_condition boolean_term boolean_factor
%type <pnval> comparison_predicate type_test

%%
query		: qstring	{ validate_parse_tree($1); }
		;

qstring		: /* NULL */	{ $$ = NULL; }
		| search_condition
		;

search_condition : boolean_term
		| search_condition KW_OR boolean_term	{
				nr_or_clauses++;
				$$ = mk_parse_node($2, $1, $3);
			}
		;

boolean_term	: boolean_factor
		| boolean_term KW_AND boolean_factor {
				nr_and_clauses++;
				$$ = mk_parse_node($2, $1, $3);
			}
		;

boolean_factor	: comparison_predicate
		| '(' search_condition ')'	{ $$ = $2; }
		;

comparison_predicate : serviceable_test	{
				$$ = mk_parse_node(KW_SERVICEABLE, NULL, NULL);
				nr_serviceability_tests++;
			}
		| severity_test	{
				$$ = mk_parse_node(KW_SEVERITY, NULL, NULL);
				nr_severity_tests++;
			}
		| type_test
		;

type_test	: KW_TYPE TK_EQ type_value	{
				$$ = mk_parse_node(TK_EQ, NULL, NULL);
				nr_type_eq_tests++;
				ored_types |= (1 << $3);
			}
		| KW_TYPE TK_NE type_value	{
				$$ = mk_parse_node(TK_NE, NULL, NULL);
				nr_type_ne_tests++;
				anded_types &= ~(1 << $3);
			}

type_value	: v1_type_value	{
				$$ = convert_type_to_v29($1);
				if ($$ == 0)
					(*semantic_errors)++;
			}
		;

v1_type_value	: TK_INT
		| KW_BASIC	{ $$ = SL_TYPE_BASIC; }
		| KW_OS		{ $$ = SL_TYPE_OS; }
		| KW_RTAS	{ $$ = SL_TYPE_RTAS; }
		| KW_BMC	{ $$ = SL_TYPE_BMC; }
		| KW_ENCLOSURE	{ $$ = SL_TYPE_ENCLOSURE; }
		;

severity_test	: KW_SEVERITY TK_GT severity_value { notify->severity = 1+$3; }
		| KW_SEVERITY TK_GE severity_value { notify->severity = $3; }
		| KW_SEVERITY TK_EQ severity_value { notify->severity = $3; }
		;

severity_value	: TK_INT {
				if ($1 < SL_SEV_DEBUG || SL_SEV_FATAL < $1) {
					(*semantic_errors)++;
					$$ = SL_SEV_FATAL;
				} else
					$$ = $1;
			}
		| KW_FATAL	{ $$ = SL_SEV_FATAL; }
		| KW_ERROR	{ $$ = SL_SEV_ERROR; }
		| KW_ERROR_LOCAL{ $$ = SL_SEV_ERROR_LOCAL; }
		| KW_WARNING	{ $$ = SL_SEV_WARNING; }
		| KW_EVENT	{ $$ = SL_SEV_EVENT; }
		| KW_INFO	{ $$ = SL_SEV_INFO; }
		| KW_DEBUG	{ $$ = SL_SEV_DEBUG; }
		;

serviceable_test : KW_SERVICEABLE TK_EQ TK_INT {
				if ($3 != 0 && $3 != 1) {
					(*semantic_errors)++;
					notify->serviceable_event = SL_QUERY_ALL;
				} else if ($3 == 0)
					notify->serviceable_event = SL_QUERY_NO;
				else
					notify->serviceable_event = SL_QUERY_YES;
			}
		;
%%

void
v29nfy_gram_init(const char *v1_match, struct v29_sl_notify *nfy,
							int *semantic_errs)
{
	assert(nfy);
	notify = nfy;
	nfy->event_types = all_types;
	nfy->serviceable_event = SL_QUERY_ALL;
	nfy->severity = 1;
	if (v1_match) {
		assert(semantic_errs);
		semantic_errors = semantic_errs;
		(*semantic_errors) = 0;

		nr_and_clauses = 0;
		nr_or_clauses = 0;
		nr_type_eq_tests = 0;
		nr_type_ne_tests = 0;
		nr_serviceability_tests = 0;
		nr_severity_tests = 0;

		anded_types = all_types;
		ored_types = 0;

		v29nfy_lex_init(v1_match);
	}
}

void
v29nfy_gram_fini(void)
{
	v29nfy_lex_fini();
}
