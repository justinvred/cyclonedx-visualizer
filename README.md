# CycloneDX SBOM Visualizer

A simple, web-based visualizer for CycloneDX Software Bill of Materials (SBOM) files. Upload your SBOM files and explore dependencies, components, and licensing information through an interactive interface.

## Features

- **File Upload**: Support for both JSON and XML CycloneDX SBOM formats
- **Dependency Tree Visualization**: Interactive tree view of component dependencies
- **Component Statistics**: Overview of SBOM metadata including component counts and license information
- **Component Table**: Detailed table view of all components with filtering
- **Search Functionality**: Quickly find components in the dependency tree
- **Expand/Collapse Controls**: Navigate large dependency trees easily

## Prerequisites

- Node.js (version 14 or higher)
- npm or yarn

## Installation

1. Install dependencies:
```bash
npm install
```

## Usage

1. Start the server:
```bash
npm start
```

For development with auto-reload:
```bash
npm run dev
```

2. Open your browser and navigate to:
```
http://localhost:3000
```

3. Upload a CycloneDX SBOM file (.json or .xml) using the file picker

4. Click "Visualize SBOM" to view the results

## Features Overview

### SBOM Overview Panel
Displays key statistics about your SBOM:
- SBOM format and version
- Main component name and version
- Total component count
- Number of unique licenses
- Component type diversity

### Dependency Tree
- Interactive tree visualization showing component relationships
- Click the arrow icon to expand/collapse branches
- Icons indicate component types (application, library, framework, etc.)
- Color-coded tags for component types and licenses
- Circular dependency detection

### Search & Filter
- Real-time search to find components by name
- Expand All / Collapse All buttons for quick navigation

### Components Table
- Comprehensive table listing all components
- Displays: Name, Version, Type, License, and Supplier information
- Sortable columns for easy navigation

## Supported CycloneDX Formats

This visualizer supports:
- CycloneDX JSON format (spec versions 1.2+)
- CycloneDX XML format (spec versions 1.2+)

## Project Structure

```
cyclonedx-visualizer/
├── public/
│   ├── index.html      # Main HTML interface
│   ├── app.js          # Client-side JavaScript
│   └── styles.css      # Styling
├── server.js           # Express server
├── package.json        # Dependencies
└── README.md          # Documentation
```

## Example SBOM Files

To test the visualizer, you can generate SBOM files using tools like:
- [CycloneDX CLI](https://github.com/CycloneDX/cyclonedx-cli)
- [cdxgen](https://github.com/CycloneDX/cdxgen)
- [syft](https://github.com/anchore/syft) (with CycloneDX output)

Example using cdxgen:
```bash
npm install -g @cyclonedx/cdxgen
cdxgen -o sbom.json /path/to/your/project
```

## Development

The application uses:
- **Express.js** for the server
- **Multer** for file upload handling
- Vanilla JavaScript for the frontend (no frameworks)

## License

MIT

## Contributing

Feel free to submit issues or pull requests to improve the visualizer!
