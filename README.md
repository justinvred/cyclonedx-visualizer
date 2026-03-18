# SBOM Visualizer

A simple, web-based visualizer for Software Bill of Materials (SBOM) files. Supports both CycloneDX and SPDX formats. Upload your SBOM files and explore dependencies, components, and licensing information through an interactive interface.

## Features

- **Multiple Format Support**: CycloneDX (JSON/XML) and SPDX 2.3 (JSON)
- **Format Selector**: Easy dropdown to switch between SBOM formats
- **File Upload**: Support for both JSON and XML file formats
- **Interactive Sunburst Chart**: Multi-level pie chart visualization showing dependency hierarchy
- **Click-to-Zoom**: Click on any segment to zoom into that component and its dependencies
- **Breadcrumb Navigation**: Visual path showing current location in the dependency tree
- **Hover Tooltips**: Detailed component information on hover
- **Component Statistics**: Overview of SBOM metadata including component counts and license information
- **Component Table**: Detailed table view of all components with filtering
- **Search Functionality**: Highlights matching components in both the chart and table
- **Responsive Design**: Adapts to different screen sizes while staying within viewport

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

3. Select your SBOM format from the dropdown (CycloneDX or SPDX 2.3)

4. Upload an SBOM file (.json or .xml) using the file picker

5. Click "Visualize SBOM" to view the results

## Features Overview

### SBOM Overview Panel
Displays key statistics about your SBOM:
- SBOM format and version
- Main component name and version
- Total component count
- Number of unique licenses
- Component type diversity

### Dependency Sunburst Chart
- Interactive multi-level pie chart showing component hierarchy
- **Click any segment** to zoom into that component and view its dependencies
- **Hover** over segments to see detailed component information (name, version, type, license, supplier)
- **Color-coded** segments for easy visual distinction
- **Breadcrumb navigation** showing your current position in the dependency tree
- Circular dependency detection (shown in orange)
- **Reset View** button to return to the root view

### Search & Filter
- Real-time search to find components by name
- Highlights matching components in the sunburst chart
- Filters the components table simultaneously

### Components Table
- Comprehensive table listing all components
- Displays: Name, Version, Type, License, and Supplier information
- Sortable columns for easy navigation

## Supported SBOM Formats

This visualizer supports:

### CycloneDX
- JSON format (spec versions 1.2+)
- XML format (spec versions 1.2+)

### SPDX
- JSON format (spec version 2.3)
- Automatically converts SPDX packages and relationships to visualizable format

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

The repository includes example files for testing:
- [example-sbom.json](example-sbom.json) - CycloneDX format example
- [example-spdx.json](example-spdx.json) - SPDX 2.3 format example

You can also generate SBOM files using tools like:

### CycloneDX Tools
- [CycloneDX CLI](https://github.com/CycloneDX/cyclonedx-cli)
- [cdxgen](https://github.com/CycloneDX/cdxgen)
- [syft](https://github.com/anchore/syft) (with CycloneDX output)

Example using cdxgen:
```bash
npm install -g @cyclonedx/cdxgen
cdxgen -o sbom.json /path/to/your/project
```

### SPDX Tools
- [spdx-sbom-generator](https://github.com/opensbom-generator/spdx-sbom-generator)
- [syft](https://github.com/anchore/syft) (with SPDX output)

Example using syft for SPDX:
```bash
syft /path/to/your/project -o spdx-json > sbom-spdx.json
```

## Development

The application uses:
- **Express.js** for the server
- **Multer** for file upload handling
- **D3.js** for interactive data visualization (sunburst chart)
- Vanilla JavaScript for the frontend logic

## License

MIT

## Contributing

Feel free to submit issues or pull requests to improve the visualizer!
