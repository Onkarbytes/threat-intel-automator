# # visualizer.py - Knowledge Graph Visualization for IOC Analysis Pipeline
# # Phase 6: The Knowledge Graph (Visualization)

# import json
# import os
# from pyvis.network import Network
# from database import IOCDatabase
# from utils import defang_ioc

# class ThreatVisualizer:
#     """
#     Creates interactive network graphs showing relationships between IOCs.
    
#     Uses pyvis to generate HTML/JavaScript visualizations of threat infrastructure,
#     mapping connections between IPs, domains, hashes, and URLs.
#     """
    
#     def __init__(self, output_dir='reports'):
#         """
#         Initialize the threat visualizer.
        
#         Args:
#             output_dir (str): Directory to save generated visualizations
#         """
#         self.output_dir = output_dir
#         os.makedirs(output_dir, exist_ok=True)
#         self.db = IOCDatabase()
    
#     def create_threat_map(self, analysis_data, output_filename='threat_map.html'):
#         """
#         Create an interactive threat map from analysis data.
        
#         Args:
#             analysis_data (dict): Complete analysis results from pipeline
#             output_filename (str): Name of output HTML file
            
#         Returns:
#             str: Path to generated HTML file
#         """
#         # Create network graph
#         net = Network(height="750px", width="100%", bgcolor="#ffffff", font_color="#2c3e50")
#         net.barnes_hut()
        
#         # Configure physics for better layout
#         net.set_options("""
#         var options = {
#           "physics": {
#             "barnesHut": {
#               "gravitationalConstant": -2000,
#               "centralGravity": 0.3,
#               "springLength": 95,
#               "springConstant": 0.04
#             },
#             "maxVelocity": 50,
#             "minVelocity": 0.1,
#             "solver": "barnesHut",
#             "timestep": 0.5
#           },
#           "nodes": {
#             "font": {
#               "size": 14,
#               "face": "arial"
#             }
#           },
#           "edges": {
#             "color": {
#               "inherit": false
#             },
#             "smooth": {
#               "type": "continuous"
#             }
#           }
#         }
#         """)
        
#         # Add nodes for each IOC category
#         self._add_ioc_nodes(net, analysis_data)
        
#         # Add edges based on relationships
#         self._add_relationships(net, analysis_data)
        
#         # Generate output path
#         output_path = os.path.join(self.output_dir, output_filename)
        
#         # Save the network
#         net.save_graph(output_path)
        
#         return output_path
    
#     def _add_ioc_nodes(self, net, analysis_data):
#         """
#         Add nodes for all IOCs with appropriate colors and styling.
        
#         Args:
#             net: Pyvis network object
#             analysis_data (dict): Analysis results
#         """
#         risk_analysis = analysis_data.get('risk_analysis', {})
        
#         # Color mapping for IOC types
#         color_map = {
#             'ips': '#e74c3c',      # Red for IPs
#             'domains': '#3498db',  # Blue for domains
#             'hashes': '#27ae60',   # Green for hashes
#             'urls': '#9b59b6'      # Purple for URLs
#         }
        
#         # Shape mapping for risk levels
#         shape_map = {
#             'CRITICAL': 'diamond',
#             'HIGH': 'triangle',
#             'MEDIUM': 'square',
#             'LOW': 'dot',
#             'SAFE': 'dot',
#             'UNKNOWN': 'dot'
#         }
        
#         for category, iocs in risk_analysis.items():
#             color = color_map.get(category, '#95a5a6')
            
#             for ioc, analysis in iocs.items():
#                 risk_level = analysis.get('risk_level', 'UNKNOWN')
#                 risk_score = analysis.get('risk_score', 0)
                
#                 # Use defanged IOC for display
#                 display_ioc = defang_ioc(ioc)
                
#                 # Determine node properties
#                 shape = shape_map.get(risk_level, 'dot')
#                 size = max(15, min(40, 15 + risk_score / 2))  # Size based on risk score
                
#                 # Create title with full information
#                 title = f"IOC: {ioc}\nRisk: {risk_level} ({risk_score})\nCategory: {category.upper()}"
                
#                 # Add metadata if available
#                 vt_data = analysis.get('analysis', {}).get('virustotal', {})
#                 if not vt_data.get('error'):
#                     malicious = vt_data.get('malicious_detections', 0)
#                     total = vt_data.get('total_engines', 0)
#                     title += f"\nVT: {malicious}/{total} malicious"
                
#                 abuse_data = analysis.get('analysis', {}).get('abuseipdb', {})
#                 if not abuse_data.get('error'):
#                     score = abuse_data.get('abuse_confidence_score', 0)
#                     title += f"\nAbuseIPDB: {score}% confidence"
                
#                 # Add node to network
#                 net.add_node(
#                     ioc,  # Use original IOC as node ID for linking
#                     label=display_ioc,
#                     title=title,
#                     color=color,
#                     shape=shape,
#                     size=size,
#                     font={'size': 12}
#                 )
    
#     def _add_relationships(self, net, analysis_data):
#         """
#         Add edges between related IOCs.
        
#         Args:
#             net: Pyvis network object
#             analysis_data (dict): Analysis results
#         """
#         risk_analysis = analysis_data.get('risk_analysis', {})
        
#         # For now, create relationships based on risk analysis patterns
#         # In a more advanced version, this could track which IOCs appeared together
        
#         # Connect high-risk IOCs to show threat clusters
#         high_risk_iocs = []
#         for category, iocs in risk_analysis.items():
#             for ioc, analysis in iocs.items():
#                 if analysis.get('risk_level') in ['CRITICAL', 'HIGH']:
#                     high_risk_iocs.append(ioc)
        
#         # Create edges between high-risk IOCs (representing threat clusters)
#         for i in range(len(high_risk_iocs)):
#             for j in range(i + 1, len(high_risk_iocs)):
#                 net.add_edge(
#                     high_risk_iocs[i],
#                     high_risk_iocs[j],
#                     color='#e74c3c',
#                     width=2,
#                     title="High-risk threat cluster"
#                 )
        
#         # Connect IPs to domains that have similar risk patterns
#         ips = risk_analysis.get('ips', {})
#         domains = risk_analysis.get('domains', {})
        
#         for ip, ip_analysis in ips.items():
#             ip_risk = ip_analysis.get('risk_level', 'UNKNOWN')
#             for domain, domain_analysis in domains.items():
#                 domain_risk = domain_analysis.get('risk_level', 'UNKNOWN')
                
#                 # Connect if they have similar risk levels
#                 if ip_risk == domain_risk and ip_risk in ['HIGH', 'CRITICAL']:
#                     net.add_edge(
#                         ip,
#                         domain,
#                         color='#f39c12',
#                         width=1,
#                         title=f"Related {ip_risk.lower()} risk indicators"
#                     )
        
#         # Connect hashes to IPs/domains they were found with
#         # This is a simplified version - in practice you'd track co-occurrence
#         hashes = risk_analysis.get('hashes', {})
#         for hash_ioc, hash_analysis in hashes.items():
#             hash_risk = hash_analysis.get('risk_level', 'UNKNOWN')
#             if hash_risk in ['HIGH', 'CRITICAL']:
#                 # Connect to any high-risk IPs or domains
#                 for ioc in high_risk_iocs:
#                     if ioc != hash_ioc:  # Don't connect to itself
#                         net.add_edge(
#                             hash_ioc,
#                             ioc,
#                             color='#27ae60',
#                             width=1,
#                             title="Malware hash associated with threat"
#                         )
    
#     def create_timeline_view(self, analysis_data, output_filename='threat_timeline.html'):
#         """
#         Create a timeline visualization of IOC discovery.
        
#         Args:
#             analysis_data (dict): Analysis results
#             output_filename (str): Name of output HTML file
            
#         Returns:
#             str: Path to generated HTML file
#         """
#         # For now, create a simple timeline based on risk levels
#         # In a full implementation, this would use actual timestamps
        
#         net = Network(height="600px", width="100%", bgcolor="#ffffff", font_color="#2c3e50")
#         net.set_options("""
#         var options = {
#           "layout": {
#             "hierarchical": {
#               "enabled": true,
#               "direction": "LR",
#               "sortMethod": "directed"
#             }
#           },
#           "physics": {
#             "enabled": false
#           }
#         }
#         """)
        
#         # Add timeline nodes
#         risk_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE', 'UNKNOWN']
#         y_positions = {'CRITICAL': 1, 'HIGH': 2, 'MEDIUM': 3, 'LOW': 4, 'SAFE': 5, 'UNKNOWN': 6}
        
#         risk_analysis = analysis_data.get('risk_analysis', {})
        
#         for category, iocs in risk_analysis.items():
#             color = {'ips': '#e74c3c', 'domains': '#3498db', 'hashes': '#27ae60', 'urls': '#9b59b6'}.get(category, '#95a5a6')
            
#             for ioc, analysis in iocs.items():
#                 risk_level = analysis.get('risk_level', 'UNKNOWN')
#                 y_pos = y_positions.get(risk_level, 7)
                
#                 display_ioc = defang_ioc(ioc)
#                 title = f"{category.upper()}: {ioc}\nRisk: {risk_level}"
                
#                 net.add_node(
#                     ioc,
#                     label=display_ioc,
#                     title=title,
#                     color=color,
#                     x=len(risk_order) - risk_order.index(risk_level),
#                     y=y_pos * 100,
#                     physics=False
#                 )
        
#         output_path = os.path.join(self.output_dir, output_filename)
#         net.save_graph(output_path)
        
#         return output_path
# visualizer.py - Knowledge Graph Visualization for IOC Analysis Pipeline
# Phase 6: The Knowledge Graph (Visualization)

import os
from pyvis.network import Network
from database import IOCDatabase
from utils import defang_ioc


class ThreatVisualizer:
    """
    Creates structured, readable threat graphs from dynamic IOC analysis data.
    """

    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.db = IOCDatabase()

    # ============================================================
    # MAIN THREAT MAP
    # ============================================================
    def create_threat_map(self, analysis_data, output_filename="threat_map.html"):

        net = Network(
            height="800px",
            width="100%",
            bgcolor="#020617",          # Dark SOC-style background
            font_color="#e5e7eb",
            directed=False
        )

        # 🔒 Physics tuned to STABILIZE (no flying blobs)
        net.set_options("""
        var options = {
          "physics": {
            "enabled": true,
            "barnesHut": {
              "gravitationalConstant": -900,
              "centralGravity": 0.12,
              "springLength": 140,
              "springConstant": 0.015,
              "damping": 0.85
            },
            "stabilization": {
              "enabled": true,
              "iterations": 200
            }
          },
          "nodes": {
            "borderWidth": 2,
            "font": { "size": 13, "face": "monospace" }
          },
          "edges": {
            "smooth": { "type": "dynamic" },
            "color": { "opacity": 0.6 }
          }
        }
        """)

        # 🧲 Anchor node (visual only)
        net.add_node(
            "THREAT_CORE",
            label="Threat Cluster",
            shape="hexagon",
            size=55,
            color="#111827",
            font={"size": 20, "color": "#ffffff"},
            physics=False
        )

        self._add_ioc_nodes(net, analysis_data)
        self._add_relationships(net, analysis_data)

        output_path = os.path.join(self.output_dir, output_filename)
        net.save_graph(output_path)
        return output_path

    # ============================================================
    # IOC NODES
    # ============================================================
    def _add_ioc_nodes(self, net, analysis_data):

        risk_analysis = analysis_data.get("risk_analysis", {})

        type_colors = {
            "ips": "#ef4444",
            "domains": "#3b82f6",
            "hashes": "#22c55e",
            "urls": "#a855f7"
        }

        risk_shapes = {
            "CRITICAL": "diamond",
            "HIGH": "triangle",
            "MEDIUM": "square",
            "LOW": "dot",
            "SAFE": "dot",
            "UNKNOWN": "dot"
        }

        risk_sizes = {
            "CRITICAL": 42,
            "HIGH": 34,
            "MEDIUM": 26,
            "LOW": 20,
            "SAFE": 18,
            "UNKNOWN": 18
        }

        for category, iocs in risk_analysis.items():
            color = type_colors.get(category, "#94a3b8")

            for ioc, analysis in iocs.items():
                risk = analysis.get("risk_level", "UNKNOWN")
                display = defang_ioc(ioc)

                title = (
                    f"IOC: {ioc}\n"
                    f"Type: {category.upper()}\n"
                    f"Risk: {risk}"
                )

                net.add_node(
                    ioc,
                    label=display,
                    title=title,
                    color=color,
                    shape=risk_shapes.get(risk, "dot"),
                    size=risk_sizes.get(risk, 18)
                )

                # Anchor HIGH / CRITICAL nodes
                if risk in ["HIGH", "CRITICAL"]:
                    net.add_edge(
                        "THREAT_CORE",
                        ioc,
                        width=2,
                        color="#f97316",
                        title="High-risk indicator"
                    )

    # ============================================================
    # RELATIONSHIPS (CONTROLLED, NOT FULL MESH)
    # ============================================================
    def _add_relationships(self, net, analysis_data):

        risk_analysis = analysis_data.get("risk_analysis", {})

        # Collect high-risk IOCs
        high_risk = {
            ioc
            for group in risk_analysis.values()
            for ioc, a in group.items()
            if a.get("risk_level") in ["HIGH", "CRITICAL"]
        }

        # 🔗 LIMITED linking: only 1–2 edges per IOC
        max_links = 2
        linked = set()

        for category, iocs in risk_analysis.items():
            for ioc, analysis in iocs.items():
                if ioc not in high_risk:
                    continue

                count = 0
                for other in high_risk:
                    if other == ioc:
                        continue
                    key = tuple(sorted([ioc, other]))
                    if key in linked:
                        continue

                    net.add_edge(
                        ioc,
                        other,
                        width=1,
                        color="#ef4444",
                        title="High-risk correlation"
                    )

                    linked.add(key)
                    count += 1
                    if count >= max_links:
                        break

    # ============================================================
    # TIMELINE VIEW (CLEAN + STATIC)
    # ============================================================
    def create_timeline_view(self, analysis_data, output_filename="threat_timeline.html"):

        net = Network(
            height="600px",
            width="100%",
            bgcolor="#020617",
            font_color="#e5e7eb"
        )

        net.set_options("""
        var options = {
          "layout": {
            "hierarchical": {
              "enabled": true,
              "direction": "LR",
              "nodeSpacing": 160
            }
          },
          "physics": { "enabled": false }
        }
        """)

        risk_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE", "UNKNOWN"]
        risk_analysis = analysis_data.get("risk_analysis", {})

        x_pos = {r: i * 250 for i, r in enumerate(risk_order)}

        for category, iocs in risk_analysis.items():
            color = {
                "ips": "#ef4444",
                "domains": "#3b82f6",
                "hashes": "#22c55e",
                "urls": "#a855f7"
            }.get(category, "#94a3b8")

            for ioc, analysis in iocs.items():
                risk = analysis.get("risk_level", "UNKNOWN")
                net.add_node(
                    ioc,
                    label=defang_ioc(ioc),
                    color=color,
                    x=x_pos.get(risk, 1500),
                    y=100,
                    physics=False
                )

        output_path = os.path.join(self.output_dir, output_filename)
        net.save_graph(output_path)
        return output_path
