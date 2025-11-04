# HAProxy Backend UI

This project provides a user interface for editing and managing individual backends in an HAProxy configuration. It allows users to easily modify backend settings and restart backends as needed.

## Features

- Load and display HAProxy configuration files.
- Edit backend settings through a user-friendly interface.
- Restart individual backends directly from the UI.
- Validate configurations before applying changes.

## Project Structure

```
haproxy-backend-ui
├── src
│   ├── main.py               # Entry point of the application
│   ├── ui                    # User interface components
│   │   ├── __init__.py
│   │   ├── main_window.py     # Main window for the UI
│   │   └── dialogs.py         # Dialogs for user interactions
│   ├── core                  # Core functionality
│   │   ├── __init__.py
│   │   ├── parser.py          # Configuration file parser
│   │   ├── manager.py         # Backend management
│   │   └── config.py          # Configuration constants
│   ├── services              # Service-related functionality
│   │   ├── __init__.py
│   │   └── reloader.py        # Logic for restarting HAProxy
│   └── utils                 # Utility functions
│       └── __init__.py
├── tests                     # Unit tests
│   ├── test_parser.py
│   └── test_manager.py
├── examples                  # Example configuration file
│   └── haproxy.cfg
├── pyproject.toml           # Project configuration
├── requirements.txt          # Required Python packages
├── .gitignore                # Files to ignore in version control
└── README.md                 # Project documentation
```

## Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   cd haproxy-backend-ui
   ```

2. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

## Usage

To start the application, run the following command:
```
python src/main.py
```

This will launch the user interface, allowing you to load an HAProxy configuration file and manage backends.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any enhancements or bug fixes.

## License

This project is licensed under the MIT License. See the LICENSE file for details.