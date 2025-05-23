#!/usr/bin/env python3
"""
Development Runner for Recon Tool.
This script allows running the tool directly from the source tree
by adjusting the Python path.
"""
import os
import sys

def main():
    """
    Set up the Python path and run the CLI.
    """
    # Add the project root directory (parent of 'recon_tool' package) to sys.path
    # This makes 'from recon_tool import ...' work.
    project_root = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, project_root)

    try:
        from recon_tool.main import main_entry # Or 'cli' if you prefer the Click object
        # Call the main entry point of your CLI application
        main_entry() # Or cli(standalone_mode=False) or just cli()
    except ImportError as e:
        print(f"Error: Could not import the Recon Tool application. Ensure you are in the project root.")
        print(f"Import Error: {e}")
        print(f"Current sys.path: {sys.path}")
        sys.exit(1)
    except Exception as e:
        # Catch any other exception during CLI execution for graceful exit
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()