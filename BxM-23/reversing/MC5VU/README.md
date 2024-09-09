# MC5VU

We're given a script
and 2 Document
Document 1.txt
Document 2.txt

```python
import math
import hashlib
import sys
SIZE = int(3e5)
VERIFY_KEY = "46e1b8845b40bc9d977b8932580ae44c"

def getSequence(A, B, n, m):
   ans = [0] * (n + m - 1)
   for x in range(n):
       for y in range(m):
           ans[x + y] += A[x] * B[y]
   return ans

A = [0] * SIZE
B = [0] * SIZE
document1 = open("Document 1.txt", "r")
nums1 = document1.readlines()
idx = 0

for num in nums1:
   A[idx] = int(num.strip())
   idx += 1

document2 = open("Document 2.txt", "r")
nums2 = document2.readlines()

idx = 0
for num in nums2:
   B[idx] = int(num.strip())
   idx += 1

sequence = getSequence(A, B, SIZE, SIZE)
val = 0

for num in sequence:
   val = (val + num)

val = str(val)
val_md5 = hashlib.md5(val.encode()).hexdigest()

if val_md5 != VERIFY_KEY:
   print("Wrong solution.")
   sys.exit(1)

key = str(hashlib.sha256(val.encode()).digest())
flag = "ctf{" + "".join(list([x for x in key if x.isalpha() or x.isnumeric()])) + "}"
print(flag)
```

# Analysis

Code uses nested for loops to perform the sequence manipulation, resulting in a time complexity of **O(n\*m)**, where **n** and **m** are the sizes of the input sequences. This approach requires iterating over all possible combinations of elements from **A** and **B** to calculate the result. As a result, the execution time increases significantly with large input sizes.n time.

# Solution

We need to optimize the code

- Use **numpy** for Sequence Manipulation: Replace the nested loops in Code with **numpy** functions for sequence manipulation. Specifically, replace the nested loops responsible for multiplying elements from **A** and **B** with a single line that uses **numpy** convolve function. This function performs convolution efficiently and handles the reversed sequence automatically, eliminating the need for explicit reversal.
- Utilize Fixed-Size **numpy** Arrays: Instead of using regular Python lists (**A** and **B**), switch to fixed-size **numpy** arrays. Use **numpy** zero to initialize the arrays with a fixed size equal to **SIZE**. Fixed-size arrays provide efficient memory allocation and optimized element access, resulting in improved performance.
- Optimize File Handling: Modify the file handling in Code 1 to adopt the same approach as Code 2. Utilize the **with** statement to ensure proper file handling and closing, reducing the likelihood of resource leaks.
- Streamline Value Conversion and Assignment: Optimize the conversion and assignment of values from the input files to the **numpy** arrays. Use **numpy** array in conjunction with a list comprehension to convert the values from the file directly into a **numpy** array, rather than iterating over the values and assigning them one by one.
- Calculate the Sum Using **numpy** sum Replace the manual accumulation of values in a loop with the **numpy** sum function to calculate the sum of the sequence. This leverages the optimized **numpy** function for efficient and faster computation of the sum.

and here is the solver script

```python
import math
import hashlib
import sys
import numpy as np
SIZE = int(3e5)
VERIFY_KEY = "46e1b8845b40bc9d977b8932580ae44c"
def getSequence(A, B):
   # Perform convolution of reversed A with B
   return np.convolve(A[::-1], B)

A = np.zeros(SIZE)
B = np.zeros(SIZE)

with open("Document 1.txt", "r") as document1:
   nums1 = document1.readlines()
   A[:len(nums1)] = np.array([int(num.strip()) for num in nums1])

with open("Document 2.txt", "r") as document2:
   nums2 = document2.readlines()
   B[:len(nums2)] = np.array([int(num.strip()) for num in nums2])

sequence = getSequence(A, B)
val = int(np.sum(sequence))

val_md5 = hashlib.md5(str(val).encode()).hexdigest()
if val_md5 != VERIFY_KEY:
   print("Wrong solution.")
   sys.exit(1)

key = str(hashlib.sha256(str(val).encode()).digest())
flag = "ctf{" + "".join(list([x for x in key if x.isalpha() or x.isnumeric()])) + "}"

print(flag)
```

**ctf{bx8b2xdcx80x8bxafx90x16x0fxc9Cx87x99Gx8cx1dxb9x8exb4xfaLx93xcfx9dxcfyx13xb5Lxee}**
