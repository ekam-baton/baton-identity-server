import os
import json
import webbrowser

def build_tree(startpath):
    nodes = []
    links = []
    node_id_map = {}
    current_id = 0

    def get_node_id(path, name, type_str):
        nonlocal current_id
        if path not in node_id_map:
            node_id_map[path] = current_id
            nodes.append({"id": current_id, "name": name, "type": type_str, "val": 2 if type_str == "file" else 5})
            current_id += 1
        return node_id_map[path]

    # Add root
    root_id = get_node_id(startpath, os.path.basename(startpath), "directory")

    for root, dirs, files in os.walk(startpath):
        # Exclude hidden directories like .git and target folder
        dirs[:] = [d for d in dirs if not d.startswith('.') and d != 'target' and d != 'node_modules']
        
        parent_id = get_node_id(root, os.path.basename(root), "directory")
        
        for d in dirs:
            dir_path = os.path.join(root, d)
            child_id = get_node_id(dir_path, d, "directory")
            links.append({"source": parent_id, "target": child_id})
            
        for f in files:
            if f.startswith('.'): continue
            file_path = os.path.join(root, f)
            child_id = get_node_id(file_path, f, "file")
            links.append({"source": parent_id, "target": child_id})

    return {"nodes": nodes, "links": links}

if __name__ == "__main__":
    project_path = r"C:\Users\yrish\.gemini\antigravity\scratch\baton-identity-server"
    data = build_tree(project_path)
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Organic Codebase Visualizer</title>
        <style>
            body {{ margin: 0; overflow: hidden; background-color: #0f172a; color: white; font-family: 'Inter', sans-serif; }}
            #graph {{ width: 100vw; height: 100vh; }}
            .tooltip {{
                position: absolute;
                padding: 8px 12px;
                background: rgba(15, 23, 42, 0.9);
                border: 1px solid #334155;
                border-radius: 6px;
                color: #e2e8f0;
                font-size: 14px;
                pointer-events: none;
                opacity: 0;
                transition: opacity 0.2s;
            }}
        </style>
        <script src="https://unpkg.com/force-graph"></script>
    </head>
    <body>
        <div id="graph"></div>
        <script>
            const data = {json.dumps(data)};
            
            const elem = document.getElementById('graph');
            const Graph = ForceGraph()(elem)
                .graphData(data)
                .nodeLabel('name')
                .nodeAutoColorBy('type')
                .nodeVal('val')
                .linkDirectionalParticles(2)
                .linkDirectionalParticleSpeed(d => 0.005)
                .linkColor(() => '#334155')
                .backgroundColor('#0f172a')
                .onNodeClick(node => {{
                    // Center/zoom on node
                    Graph.centerAt(node.x, node.y, 1000);
                    Graph.zoom(8, 2000);
                }});
                
            // Custom node rendering to make it organic
            Graph.nodeCanvasObject((node, ctx, globalScale) => {{
                const label = node.name;
                const fontSize = 12/globalScale;
                ctx.font = `${{fontSize}}px Sans-Serif`;
                const textWidth = ctx.measureText(label).width;
                const bckgDimensions = [textWidth, fontSize].map(n => n + fontSize * 0.2); 

                ctx.fillStyle = 'rgba(15, 23, 42, 0.8)';
                ctx.fillRect(node.x - bckgDimensions[0] / 2, node.y - bckgDimensions[1] / 2, ...bckgDimensions);

                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillStyle = node.type === 'directory' ? '#38bdf8' : '#a78bfa';
                
                // Draw circle
                ctx.beginPath();
                ctx.arc(node.x, node.y, node.type === 'directory' ? 6 : 3, 0, 2 * Math.PI, false);
                ctx.fill();
                
                // Draw text below
                ctx.fillStyle = '#e2e8f0';
                ctx.fillText(label, node.x, node.y + 8);
            }});
        </script>
    </body>
    </html>
    """
    
    output_path = os.path.join(project_path, "visualize.html")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
        
    print(f"Generated visualization at {{output_path}}")
    webbrowser.open('file://' + os.path.realpath(output_path))
