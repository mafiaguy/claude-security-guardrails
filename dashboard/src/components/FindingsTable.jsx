import { useState, useMemo } from 'react';

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

function FindingsTable({ findings }) {
  const [sortField, setSortField] = useState('severity');
  const [sortDir, setSortDir] = useState('asc');
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [filterCategory, setFilterCategory] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');

  const handleSort = (field) => {
    if (sortField === field) {
      setSortDir(sortDir === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDir('asc');
    }
  };

  const filtered = useMemo(() => {
    let result = [...findings];

    if (filterSeverity !== 'all') {
      result = result.filter(f => f.severity === filterSeverity);
    }
    if (filterCategory !== 'all') {
      result = result.filter(f => f.category === filterCategory);
    }
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      result = result.filter(f =>
        f.file.toLowerCase().includes(term) ||
        f.rule.toLowerCase().includes(term) ||
        f.description.toLowerCase().includes(term)
      );
    }

    result.sort((a, b) => {
      let cmp = 0;
      if (sortField === 'severity') {
        cmp = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
      } else if (sortField === 'file') {
        cmp = a.file.localeCompare(b.file);
      } else if (sortField === 'category') {
        cmp = a.category.localeCompare(b.category);
      } else if (sortField === 'rule') {
        cmp = a.rule.localeCompare(b.rule);
      } else if (sortField === 'line') {
        cmp = a.line - b.line;
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });

    return result;
  }, [findings, filterSeverity, filterCategory, searchTerm, sortField, sortDir]);

  const categories = [...new Set(findings.map(f => f.category))];
  const sortIndicator = (field) =>
    sortField === field ? (sortDir === 'asc' ? ' ↑' : ' ↓') : '';

  return (
    <>
      <h3>Findings Detail</h3>
      <div className="findings-controls">
        <select
          value={filterSeverity}
          onChange={e => setFilterSeverity(e.target.value)}
        >
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select
          value={filterCategory}
          onChange={e => setFilterCategory(e.target.value)}
        >
          <option value="all">All Categories</option>
          {categories.map(c => (
            <option key={c} value={c}>{c}</option>
          ))}
        </select>
        <input
          type="text"
          placeholder="Search files, rules, descriptions..."
          value={searchTerm}
          onChange={e => setSearchTerm(e.target.value)}
        />
      </div>

      {filtered.length === 0 ? (
        <div className="no-findings">
          {findings.length === 0 ? 'No security findings - clean!' : 'No findings match your filters'}
        </div>
      ) : (
        <table className="findings-table">
          <thead>
            <tr>
              <th onClick={() => handleSort('severity')}>
                Severity{sortIndicator('severity')}
              </th>
              <th onClick={() => handleSort('category')}>
                Category{sortIndicator('category')}
              </th>
              <th onClick={() => handleSort('rule')}>
                Rule{sortIndicator('rule')}
              </th>
              <th onClick={() => handleSort('file')}>
                Location{sortIndicator('file')}
              </th>
              <th>Description</th>
              <th>Snippet</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((f, i) => (
              <tr key={`${f.file}-${f.line}-${f.rule}-${i}`}>
                <td>
                  <span className={`severity-badge ${f.severity}`}>
                    {f.severity}
                  </span>
                </td>
                <td>{f.category}</td>
                <td>{f.rule}</td>
                <td><code>{f.file}:{f.line}</code></td>
                <td>{f.description}</td>
                <td><span className="snippet">{f.snippet}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <div style={{ marginTop: 12, color: 'var(--text-muted)', fontSize: '0.8em' }}>
        Showing {filtered.length} of {findings.length} findings
      </div>
    </>
  );
}

export default FindingsTable;
