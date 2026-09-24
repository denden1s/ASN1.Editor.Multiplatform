import { useEffect } from 'react';
import type { AsnNode } from '../asn1';
import { childNodes, nodeTotal, nodeValue } from '../asn1';

interface TreeViewProps {
  root: AsnNode;
  selectedOffset: number | null;
  collapsed: Set<number>;
  onSelect: (node: AsnNode) => void;
  onToggle: (offset: number) => void;
}

export function TreeView({ root, selectedOffset, collapsed, onSelect, onToggle }: TreeViewProps) {
  useEffect(() => {
    if (selectedOffset === null) {
      return;
    }
    document.querySelector(`[data-node="${selectedOffset}"]`)?.scrollIntoView({ block: 'nearest' });
  }, [selectedOffset]);

  return (
    <div className="tree" role="tree" aria-label="ASN.1 structure">
      <TreeNode
        node={root}
        depth={0}
        selectedOffset={selectedOffset}
        collapsed={collapsed}
        onSelect={onSelect}
        onToggle={onToggle}
      />
    </div>
  );
}

interface NodeProps extends Omit<TreeViewProps, 'root'> {
  node: AsnNode;
  depth: number;
}

function TreeNode({ node, depth, selectedOffset, collapsed, onSelect, onToggle }: NodeProps) {
  const kids = childNodes(node);
  const isCollapsed = collapsed.has(node.offset);
  const isSelected = selectedOffset === node.offset;
  const val = nodeValue(node);

  return (
    <>
      <div
        className={isSelected ? 'tnode selected' : 'tnode'}
        data-node={node.offset}
        role="treeitem"
        aria-selected={isSelected}
        aria-expanded={kids.length > 0 ? !isCollapsed : undefined}
        style={{ paddingLeft: 8 + depth * 14 }}
        onClick={() => onSelect(node)}
      >
        <button
          className="twisty"
          disabled={kids.length === 0}
          aria-label={isCollapsed ? 'Expand' : 'Collapse'}
          onClick={(e) => {
            e.stopPropagation();
            onToggle(node.offset);
          }}
        >
          {kids.length === 0 ? '·' : isCollapsed ? '▸' : '▾'}
        </button>
        <span className="tname">{node.tagName}</span>
        {node.oidName && <span className="oid">{node.oidName}</span>}
        <span className="ttag">{node.tag}</span>
        {val && (
          <span className="tval" title={val}>
            {val}
          </span>
        )}
        <span className="tmeta">
          @{node.offset} · l={node.length} · +{node.headerLen} hdr · {nodeTotal(node)} B
        </span>
      </div>
      {kids.length > 0 && !isCollapsed && (
        <div role="group">
          {kids.map((k) => (
            <TreeNode
              key={k.offset}
              node={k}
              depth={depth + 1}
              selectedOffset={selectedOffset}
              collapsed={collapsed}
              onSelect={onSelect}
              onToggle={onToggle}
            />
          ))}
        </div>
      )}
    </>
  );
}
