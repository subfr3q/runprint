from pathlib import Path

output = Path("result.txt")
output.write_text("hello from the sandbox\n")
print(output.read_text(), end="")
