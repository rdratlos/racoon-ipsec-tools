/* A Bison parser, made by GNU Bison 2.6.2.  */

/* Bison interface for Yacc-like parsers in C
   
      Copyright (C) 1984, 1989-1990, 2000-2012 Free Software Foundation, Inc.
   
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

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

#ifndef _LIBIPSEC_POLICY_PARSE_H
# define _LIBIPSEC_POLICY_PARSE_H
/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int __libipsecdebug;
#endif

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     DIR = 258,
     PRIORITY = 259,
     PLUS = 260,
     PRIO_BASE = 261,
     PRIO_OFFSET = 262,
     ACTION = 263,
     PROTOCOL = 264,
     MODE = 265,
     LEVEL = 266,
     LEVEL_SPECIFY = 267,
     IPADDRESS = 268,
     PORT = 269,
     ME = 270,
     ANY = 271,
     SLASH = 272,
     HYPHEN = 273
   };
#endif
/* Tokens.  */
#define DIR 258
#define PRIORITY 259
#define PLUS 260
#define PRIO_BASE 261
#define PRIO_OFFSET 262
#define ACTION 263
#define PROTOCOL 264
#define MODE 265
#define LEVEL 266
#define LEVEL_SPECIFY 267
#define IPADDRESS 268
#define PORT 269
#define ME 270
#define ANY 271
#define SLASH 272
#define HYPHEN 273



#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
{
/* Line 2049 of yacc.c  */
#line 129 "policy_parse.y"

	u_int num;
	u_int32_t num32;
	struct _val {
		int len;
		char *buf;
	} val;


/* Line 2049 of yacc.c  */
#line 103 "policy_parse.h"
} YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
#endif

extern YYSTYPE __libipseclval;

#ifdef YYPARSE_PARAM
#if defined __STDC__ || defined __cplusplus
int __libipsecparse (void *YYPARSE_PARAM);
#else
int __libipsecparse ();
#endif
#else /* ! YYPARSE_PARAM */
#if defined __STDC__ || defined __cplusplus
int __libipsecparse (void);
#else
int __libipsecparse ();
#endif
#endif /* ! YYPARSE_PARAM */

#endif /* !_LIBIPSEC_POLICY_PARSE_H  */
