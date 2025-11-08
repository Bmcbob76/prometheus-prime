# PROMPT FOR CLAUDE: Complete MCP Server Setup for Cline

## Objective
Get Cline complete access to all available MCP/HTTPS servers so I can fully utilize their tools and resources.

## Current Situation Analysis
Cline (the AI assistant) currently has:
- **MCP tool capabilities**: `use_mcp_tool`, `access_mcp_resource`, `load_mcp_documentation`
- **Current limitation**: Cannot discover or enumerate connected MCP servers
- **Error encountered**: "No connection found for server: crystal-memory-hub"
- **Critical gap**: No ability to list available MCP servers or their tools

## Required Actions for Claude

### 1. IDENTIFY AND CONNECT MCP SERVERS
- **Discover all available MCP servers** in the environment
- **Connect ALL MCP servers** to Cline's configuration
- **Verify server connections** are active and accessible

### 2. COMPREHENSIVE MCP SERVER INTEGRATION
Connect these types of MCP servers:
- **Local MCP servers** (filesystem, databases, system tools)
- **HTTPS/Web-based MCP servers** (APIs, web services, external tools)
- **Specialized MCP servers** (memory hubs, analytics, monitoring tools)
- **Custom MCP servers** (any project-specific servers)

### 3. CONFIGURATION REQUIREMENTS
- **Update Cline's MCP configuration** to include ALL available servers
- **Ensure proper authentication** for HTTPS/secure servers
- **Set up server discovery mechanisms** so Cline can enumerate available tools
- **Configure server permissions** for full tool access

### 4. SPECIFIC SERVERS TO CONNECT
Based on environment context, ensure these are connected:
- **crystal-memory-hub** (mentioned in previous attempts)
- **Any Prometheus/Gateway-related MCP servers**
- **OSINT/Intelligence API servers**
- **Database/Storage MCP servers**
- **Network/System monitoring MCP servers**

### 5. VERIFICATION AND TESTING
- **Implement server enumeration** - Cline must be able to list all connected MCP servers
- **Test tool discovery** - Cline must see all available tools from each server
- **Verify resource access** - Cline must access all MCP resources
- **Document server capabilities** - Create a comprehensive list of available MCP tools

## Expected Outcome
After completion, Cline should be able to:
- **List all connected MCP servers** and their available tools
- **Use any MCP tool** without "connection not found" errors
- **Access all MCP resources** (files, APIs, databases, etc.)
- **Discover new tools automatically** as servers are added
- **Provide comprehensive tool listings** when requested

## Technical Implementation Details
- **MCP Configuration Files**: Locate and update all relevant MCP configuration files
- **Server Discovery Protocol**: Implement or enable server enumeration capabilities
- **Tool Registration**: Ensure all MCP tools are properly registered and accessible
- **Connection Testing**: Validate each server connection and tool functionality
- **Error Handling**: Set up proper error reporting for connection issues

## Success Criteria
- Cline can successfully execute: `use_mcp_tool` for ANY available MCP server
- Cline can list ALL connected MCP servers and their tools when asked
- No "connection not found" errors for any MCP operations
- Full access to HTTPS-based MCP servers with proper authentication
- Complete tool discovery and enumeration capabilities

## Urgency
**HIGH PRIORITY** - Without MCP server access, Cline cannot utilize critical tools and resources needed for comprehensive task execution in the Prometheus Prime environment.
