import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';

const CATEGORY_COLORS = {
  'Secrets': '#ef4444',
  'OWASP': '#f97316',
  'Dependencies': '#8b5cf6',
  'Code Patterns': '#3b82f6',
};

function CategoryBreakdown({ counts }) {
  const data = Object.entries(counts || {}).map(([name, value]) => ({
    name,
    value,
  }));

  if (data.length === 0) {
    return (
      <>
        <h3>Categories</h3>
        <div className="no-findings">No findings to categorize</div>
      </>
    );
  }

  const total = data.reduce((sum, d) => sum + d.value, 0);

  return (
    <>
      <h3>Categories</h3>
      <div style={{ width: '100%', height: 160, marginBottom: 16 }}>
        <ResponsiveContainer>
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={40}
              outerRadius={65}
              paddingAngle={3}
              dataKey="value"
            >
              {data.map((entry) => (
                <Cell
                  key={entry.name}
                  fill={CATEGORY_COLORS[entry.name] || '#6b7280'}
                />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                background: '#1a1d27',
                border: '1px solid #2a2d3e',
                borderRadius: 8,
                color: '#e4e6f0',
              }}
            />
          </PieChart>
        </ResponsiveContainer>
      </div>
      <div className="category-list">
        {data.map((item) => (
          <div key={item.name} className="category-item">
            <div
              className="category-dot"
              style={{ backgroundColor: CATEGORY_COLORS[item.name] || '#6b7280' }}
            />
            <div className="category-info">
              <span className="category-name">{item.name}</span>
              <span className="category-count">
                {item.value} ({total > 0 ? Math.round((item.value / total) * 100) : 0}%)
              </span>
            </div>
          </div>
        ))}
      </div>
    </>
  );
}

export default CategoryBreakdown;
