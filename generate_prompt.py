import os

# --- CONFIGURATION ---
# 1. Set the main coding prompt that will be at the top of the generated file.
USER_PROMPT = """
I need you tell me how to update the code to also work with the gemini api


"""

# 2. Add the file extensions you want to include in the context.
FILE_EXTENSION_WHITELIST = [
    '.py',
    '.html',
    '.css',
    '.js',
    '.txt',
   # '.md',
    #'.json',
    # Add other file types as needed
]

# 3. Add the names of folders to completely ignore.
FOLDER_BLACKLIST = [
    '.git',
    '__pycache__',
    '.venv',
    '.idea',
    'node_modules',
    "Clean_Chats",
    "gguf_models",
    "llama.cpp",
    "logs",
    "output_models",
    "Raw_data",
    "Training_data",
    "unsloth_compiled_cache",
    "Scraps"
    # Add other folder names to exclude
]

# 4. Add the exact names of any files to ignore.
FILE_BLACKLIST = [
    'generate_prompt.py',  # To prevent the script from reading itself
    'llm_prompt.txt',   # To prevent it from reading its own output
    ".gitignore"      
    # Add other specific file names to exclude
]

# 5. Define the name of the output file.
OUTPUT_FILENAME = 'llm_prompt.txt'

def generate_llm_prompt():
    """
    Generates a text file containing a user-defined prompt and the
    concatenated text from whitelisted files in the current directory structure.
    """
    # Start with the user's main prompt
    final_prompt = USER_PROMPT.strip() + "\n\n" + "="*50 + "\n\n" + "CONTEXT FROM FILES:\n\n"

    # Recursively walk through the current directory
    for root, dirs, files in os.walk('.', topdown=True):
        # Exclude blacklisted directories from the search
        # The '[:]' is a slice assignment that modifies the list in place
        dirs[:] = [d for d in dirs if d not in FOLDER_BLACKLIST]

        for filename in files:
            # Check if the file is in the file blacklist
            if filename in FILE_BLACKLIST:
                continue

            # Check if the file has a whitelisted extension
            if any(filename.endswith(ext) for ext in FILE_EXTENSION_WHITELIST):
                file_path = os.path.join(root, filename)

                #Print found
                print(f"Found file: {file_path}")

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                        content = file.read()
                        final_prompt += f"--- START OF FILE: {file_path} ---\n\n"
                        final_prompt += content
                        final_prompt += f"\n\n--- END OF FILE: {file_path} ---\n\n"
                except Exception as e:
                    final_prompt += f"--- COULD NOT READ FILE: {file_path} (Error: {e}) ---\n\n"

    # Write the combined content to the output file
    try:
        with open(OUTPUT_FILENAME, 'w', encoding='utf-8') as output_file:
            output_file.write(final_prompt)
        print(f"Successfully generated prompt file: '{OUTPUT_FILENAME}'")
    except Exception as e:
        print(f"Error writing to output file: {e}")

if __name__ == '__main__':
    generate_llm_prompt()