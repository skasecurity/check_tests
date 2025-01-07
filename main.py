import redshift_connector

def demonstrate_vulnerability_v2_1_4():
    """
    Demonstrates the SQL injection vulnerability in v2.1.4.
    DO NOT USE THIS IN PRODUCTION - FOR EDUCATIONAL PURPOSES ONLY.
    """
    try:
        # Create connection
        conn = redshift_connector.connect(
            host='your-cluster.region.redshift.amazonaws.com',
            database='your_database',
            user='your_username',
            password='your_password'
        )
        
        # Vulnerable metadata calls in v2.1.4
        # These methods directly interpolate user input into SQL queries
        cursor = conn.cursor()
        
        # Potential injection point in schema name
        malicious_schema = "public; DROP TABLE sensitive_data; --"
        cursor.get_schemas(schema_pattern=malicious_schema)
        
        # Potential injection point in table name
        malicious_table = "users; DELETE FROM audit_logs; --"
        cursor.get_tables(table_pattern=malicious_table)
        
        # Potential injection point in column name
        malicious_column = "id; GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO malicious_user; --"
        cursor.get_columns(column_pattern=malicious_column)
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if 'conn' in locals():
            conn.close()

def secure_implementation_v2_1_5():
    """
    Demonstrates the secure implementation in v2.1.5 using parameterized queries.
    This is the recommended approach.
    """
    try:
        # Create connection
        conn = redshift_connector.connect(
            host='your-cluster.region.redshift.amazonaws.com',
            database='your_database',
            user='your_username',
            password='your_password'
        )
        
        cursor = conn.cursor()
        
        # Safe metadata calls in v2.1.5
        # These methods use QUOTE_IDENT and QUOTE_LITERAL internally
        
        # Schema query - safely quoted
        schema_name = "public"
        cursor.get_schemas(schema_pattern=schema_name)
        
        # Table query - safely quoted
        table_name = "users"
        cursor.get_tables(table_pattern=table_name)
        
        # Column query - safely quoted
        column_name = "id"
        cursor.get_columns(column_pattern=column_name)
        
        # Example of custom query using parameters
        safe_query = """
        SELECT * FROM information_schema.tables 
        WHERE table_schema = %s AND table_name = %s
        """
        cursor.execute(safe_query, (schema_name, table_name))
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if 'conn' in locals():
            conn.close()

def best_practices():
    """
    Demonstrates additional security best practices when working with Redshift.
    """
    try:
        # Use environment variables for sensitive information
        from os import environ
        
        conn = redshift_connector.connect(
            host=environ.get('REDSHIFT_HOST'),
            database=environ.get('REDSHIFT_DB'),
            user=environ.get('REDSHIFT_USER'),
            password=environ.get('REDSHIFT_PASSWORD'),
            ssl=True,  # Always use SSL
            timeout=10  # Set reasonable timeouts
        )
        
        cursor = conn.cursor()
        
        # Use whitelisting for schema/table names when possible
        allowed_schemas = {'public', 'sales', 'marketing'}
        schema_name = "public"
        
        if schema_name not in allowed_schemas:
            raise ValueError("Invalid schema name")
            
        # Use proper error handling
        try:
            cursor.get_schemas(schema_pattern=schema_name)
        except redshift_connector.Error as e:
            print(f"Database error: {e}")
            # Log the error appropriately
            raise
            
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    # Only run the secure implementations
    secure_implementation_v2_1_5()
    best_practices()