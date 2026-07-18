from agentguard.mcp_proxy import MCPProxy, MockMCPServer

proxy = MCPProxy(MockMCPServer())
print(proxy.call_tool("poisoned_search", {}))
print(proxy.call_tool("safe_search", {}))
