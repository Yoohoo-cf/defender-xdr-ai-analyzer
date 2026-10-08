from sentinel_client import (
    get_sentinel_access_token,
    query_sentinel,
    extract_rows
)

def main():
    # Step 1: Get access token
    access_token = get_sentinel_access_token()

    # Step 2: Define your Kusto query
    query = """
    DeviceEvents
    | summarize EventCount = count() by ActionType
    | order by EventCount desc
    | take 5
    """

    # Step 3: Query Sentinel / Log Analytics
    result = query_sentinel(access_token, query)

    # Step 4: Extract rows from the result
    rows = extract_rows(result)

    # Step 5: Display the results
    print(f"\nRows returned: {len(rows)}")
    for row in rows:
        print(row)
        print("Sentinel client test completed successfully.")

if __name__ == "__main__":
    main()