import networkx as nx
import collections

def build_heterogeneous_graph(resolved_packages, vulnerability_details, package_metadata_map):
    """
    Constructs a heterogeneous graph using NetworkX.
    Nodes: package, version, cve, maintainer
    Edges: depends_on, has_version, vulnerable_to, maintained_by
    """
    G = nx.DiGraph()
    
    # 1. Add Package and Maintainer Nodes
    for key, pkg in resolved_packages.items():
        name = pkg["name"]
        meta = package_metadata_map.get(key, {})
        
        # Add package node
        G.add_node(
            name, 
            type="package", 
            downloads=meta.get("downloads", 100000),
            stars=meta.get("stars", 100),
            forks=meta.get("forks", 10),
            openssf_score=meta.get("openssf_score", 5.5),
            age_days=meta.get("age_days", 365.0),
            release_frequency=meta.get("release_frequency", 5.0)
        )
        
        # Add version node
        version_node = f"{name}@{pkg['version']}"
        G.add_node(
            version_node,
            type="version",
            version=pkg["version"],
            patch_delay=meta.get("last_update_days", 10.0),
            release_burstiness=meta.get("release_burstiness", 0.3)
        )
        
        # Connect package to version
        G.add_edge(name, version_node, relationship="has_version")
        
        # Add maintainer
        maintainer_name = pkg.get("maintainer", meta.get("author", "Unknown"))
        if maintainer_name and maintainer_name != "Unknown":
            # Avoid duplicate maintainers
            m_node = f"maintainer:{maintainer_name}"
            G.add_node(m_node, type="maintainer", churn=meta.get("maintainer_churn", 0.1), activity=meta.get("commit_activity", 1.0))
            G.add_edge(name, m_node, relationship="maintained_by")

    # 2. Add Dependency Edges (between version nodes)
    for key, pkg in resolved_packages.items():
        version_node = f"{pkg['name']}@{pkg['version']}"
        for dep in pkg["dependencies"]:
            dep_key = dep.lower()
            if dep_key in resolved_packages:
                dep_pkg = resolved_packages[dep_key]
                dep_version_node = f"{dep_pkg['name']}@{dep_pkg['version']}"
                G.add_edge(version_node, dep_version_node, relationship="depends_on")

    # 3. Add CVE Nodes and vulnerable_to Edges
    for key, vulns in vulnerability_details.items():
        pkg = resolved_packages.get(key)
        if not pkg:
            continue
        version_node = f"{pkg['name']}@{pkg['version']}"
        
        for v in vulns:
            cve_id = v["cve_id"]
            G.add_node(
                cve_id, 
                type="cve",
                cvss_score=v.get("cvss_score", 5.0),
                cwes=",".join(v.get("cwes", ["CWE-Unknown"])),
                exploitability=v.get("exploitability", 0.5)
            )
            G.add_edge(version_node, cve_id, relationship="vulnerable_to")
            
    return G

def compute_graph_features(G, resolved_packages):
    """
    Computes graph metrics and node features for machine learning:
    PageRank, Centrality, Vulnerable Neighbor Ratio, Dependency Depth
    """
    # Create an undirected graph for clustering coefficients
    undirected_G = G.to_undirected()
    
    # Precompute NetworkX metrics
    try:
        pagerank = nx.pagerank(G, alpha=0.85)
    except Exception:
        pagerank = {node: 1.0/max(len(G), 1) for node in G.nodes()}
        
    try:
        betweenness = nx.betweenness_centrality(G)
    except Exception:
        betweenness = {node: 0.0 for node in G.nodes()}
        
    try:
        degree_centrality = nx.degree_centrality(G)
    except Exception:
        degree_centrality = {node: 0.0 for node in G.nodes()}
        
    try:
        clustering = nx.clustering(undirected_G)
    except Exception:
        clustering = {node: 0.0 for node in G.nodes()}

    # Compute dependency depth from top-level nodes
    # Find nodes that have no incoming depends_on links
    package_nodes = [node for node, attr in G.nodes(data=True) if attr.get("type") == "package"]
    version_nodes = [node for node, attr in G.nodes(data=True) if attr.get("type") == "version"]
    
    # Roots in dependency chain
    roots = []
    for vn in version_nodes:
        in_depends = False
        for u, v, k in G.in_edges(vn, data=True):
            if k.get("relationship") == "depends_on":
                in_depends = True
                break
        if not in_depends:
            roots.append(vn)
            
    # Calculate depth using shortest paths from roots
    depths = {}
    for r in roots:
        for vn in version_nodes:
            try:
                path_len = nx.shortest_path_length(G, source=r, target=vn)
                depths[vn] = min(depths.get(vn, 999), path_len)
            except nx.NetworkXNoPath:
                pass
                
    # Normalize depth
    for vn in version_nodes:
        if vn not in depths or depths[vn] == 999:
            depths[vn] = 0

    # Calculate vulnerable neighbor ratios & blast radius
    vuln_ratios = {}
    blast_radius = {}
    
    for vn in version_nodes:
        # 1. Vulnerable neighbor ratios
        descendants = nx.descendants(G, vn)
        desc_versions = [d for d in descendants if G.nodes[d].get("type") == "version"]
        
        if not desc_versions:
            vuln_ratios[vn] = 0.0
        else:
            vuln_desc_count = 0
            for dv in desc_versions:
                has_cve = any(G.nodes[target].get("type") == "cve" for target in G.successors(dv))
                if has_cve:
                    vuln_desc_count += 1
            vuln_ratios[vn] = float(vuln_desc_count) / len(desc_versions)
            
        # 2. Blast Radius (number of upstream package dependents)
        dependents = nx.ancestors(G, vn)
        dependent_versions = [d for d in dependents if G.nodes[d].get("type") == "version"]
        blast_radius[vn] = len(dependent_versions)

    # Return structured node features
    features = {}
    for key, pkg in resolved_packages.items():
        pkg_name = pkg["name"]
        version_node = f"{pkg_name}@{pkg['version']}"
        
        features[key] = {
            "dependency_depth": depths.get(version_node, 0),
            "pagerank": pagerank.get(pkg_name, 0.0) + pagerank.get(version_node, 0.0),
            "betweenness_centrality": betweenness.get(pkg_name, 0.0) + betweenness.get(version_node, 0.0),
            "node_centrality": degree_centrality.get(pkg_name, 0.0) + degree_centrality.get(version_node, 0.0),
            "clustering_coefficient": clustering.get(pkg_name, 0.0) + clustering.get(version_node, 0.0),
            "vulnerable_neighbor_ratio": vuln_ratios.get(version_node, 0.0),
            "blast_radius": blast_radius.get(version_node, 0)
        }
        
    return features

def propagate_risks(G):
    """
    Implements Transitive Risk Propagation.
    Traverses the graph using BFS/DFS to identify critical attack paths and
    calculates propagated risk scores for all packages.
    """
    # Find CVE nodes
    cve_nodes = [node for node, attr in G.nodes(data=True) if attr.get("type") == "cve"]
    
    # Store dynamic risk scores propagated to nodes
    propagated_risks = collections.defaultdict(float)
    critical_attack_paths = []
    
    # For each CVE node, traverse back up to the packages
    for cve in cve_nodes:
        cvss = G.nodes[cve].get("cvss_score", 5.0)
        exploitability = G.nodes[cve].get("exploitability", 0.5)
        base_risk = (cvss / 10.0) * exploitability
        
        # Find immediate vulnerable versions
        vulnerable_versions = list(G.predecessors(cve))
        
        for version in vulnerable_versions:
            propagated_risks[version] = max(propagated_risks[version], base_risk)
            
            # DFS search upwards through 'depends_on' edges (predecessors in depends_on)
            # Find packages that import this version
            queue = [(version, [version])]
            visited = set()
            
            while queue:
                current_node, path = queue.pop(0)
                if current_node in visited:
                    continue
                visited.add(current_node)
                
                # Propagate risk upward with decay
                depth = len(path)
                decayed_risk = base_risk * (0.85 ** (depth - 1))
                propagated_risks[current_node] = max(propagated_risks[current_node], decayed_risk)
                
                # Check predecessors (who depends on this version)
                predecessors = []
                for pred in G.predecessors(current_node):
                    # verify this is a dependency edge
                    edge_data = G.get_edge_data(pred, current_node)
                    if edge_data and edge_data.get("relationship") == "depends_on":
                        predecessors.append(pred)
                        
                for pred in predecessors:
                    queue.append((pred, [pred] + path))
                    
                # If we hit a root node (no depends_on predecessors) and path is longer than 1, record attack path
                if not predecessors and len(path) > 1:
                    path_str = " -> ".join([p.split("@")[0] for p in path]) + f" [VULN: {cve}]"
                    critical_attack_paths.append({
                        "path": path_str,
                        "risk_score": decayed_risk,
                        "cve_id": cve
                    })
                    
    # Also map package level risks from version node risks
    package_risks = {}
    for node, attr in G.nodes(data=True):
        if attr.get("type") == "package":
            # Get maximum risk of its versions
            max_r = 0.0
            for succ in G.successors(node):
                if G.nodes[succ].get("type") == "version":
                    max_r = max(max_r, propagated_risks[succ])
            package_risks[node] = max_r

    return {
        "node_risk_scores": propagated_risks,
        "package_risks": package_risks,
        "attack_paths": sorted(critical_attack_paths, key=lambda x: x["risk_score"], reverse=True)
    }
