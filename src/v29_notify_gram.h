/* A Bison parser, made by GNU Bison 2.3.  */

/* Skeleton interface for Bison's Yacc-like parsers in C

   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
   Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     KW_AND = 258,
     KW_OR = 259,
     KW_TYPE = 260,
     KW_SEVERITY = 261,
     KW_SERVICEABLE = 262,
     KW_BASIC = 263,
     KW_OS = 264,
     KW_RTAS = 265,
     KW_BMC = 266,
     KW_ENCLOSURE = 267,
     KW_FATAL = 268,
     KW_ERROR = 269,
     KW_ERROR_LOCAL = 270,
     KW_WARNING = 271,
     KW_EVENT = 272,
     KW_INFO = 273,
     KW_DEBUG = 274,
     TK_INT = 275,
     TK_EQ = 276,
     TK_NE = 277,
     TK_GT = 278,
     TK_GE = 279
   };
#endif
/* Tokens.  */
#define KW_AND 258
#define KW_OR 259
#define KW_TYPE 260
#define KW_SEVERITY 261
#define KW_SERVICEABLE 262
#define KW_BASIC 263
#define KW_OS 264
#define KW_RTAS 265
#define KW_BMC 266
#define KW_ENCLOSURE 267
#define KW_FATAL 268
#define KW_ERROR 269
#define KW_ERROR_LOCAL 270
#define KW_WARNING 271
#define KW_EVENT 272
#define KW_INFO 273
#define KW_DEBUG 274
#define TK_INT 275
#define TK_EQ 276
#define TK_NE 277
#define TK_GT 278
#define TK_GE 279




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
#line 162 "v29_notify_gram.y"
{
	int ival;
	struct parse_node *pnval;
}
/* Line 1489 of yacc.c.  */
#line 102 "v29_notify_gram.h"
	YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif

extern YYSTYPE v29nfy_lval;

