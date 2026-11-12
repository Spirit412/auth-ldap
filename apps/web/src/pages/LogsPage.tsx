import { Card, Select, Tag, Space, Switch, Typography, Tooltip, Button, Table } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { fetchLogs, listLogDates, type LogEntry } from '../services/logs';

const levelColor: Record<string, string> = {
  debug: 'default',
  info: 'blue',
  warn: 'orange',
  error: 'red',
};

export function LogsPage() {
  const [date, setDate] = useState<string | undefined>();
  const [level, setLevel] = useState<string | undefined>();
  const [offset, setOffset] = useState(0);
  const [autoRefresh, setAutoRefresh] = useState(false);

  const datesQuery = useQuery({
    queryKey: ['log-dates'],
    queryFn: listLogDates,
  });

  const effectiveDate = date ?? datesQuery.data?.[0];

  const logsQuery = useQuery({
    queryKey: ['logs', effectiveDate, level, offset],
    queryFn: () => fetchLogs({ date: effectiveDate, level, offset, limit: 200 }),
    enabled: !!effectiveDate,
    refetchInterval: autoRefresh ? 10_000 : false,
  });

  const items: LogEntry[] = logsQuery.data?.items ?? [];

  return (
    <Card
      title={<Typography.Title level={5} style={{ margin: 0 }}>Логи состояния (файлы, ротация 3 дня)</Typography.Title>}
      size="small"
      extra={
        <Space wrap>
          <Select
            placeholder="Дата"
            style={{ width: 150 }}
            value={effectiveDate}
            onChange={(v) => {
              setDate(v);
              setOffset(0);
            }}
            options={(datesQuery.data ?? []).map((d) => ({ value: d, label: d }))}
          />
          <Select
            placeholder="Уровень"
            allowClear
            style={{ width: 120 }}
            value={level}
            onChange={(v) => {
              setLevel(v);
              setOffset(0);
            }}
            options={['debug', 'info', 'warn', 'error'].map((l) => ({ value: l, label: l }))}
          />
          <Tooltip title="Автообновление каждые 10 с">
            <Space>
              <Typography.Text>авто</Typography.Text>
              <Switch size="small" checked={autoRefresh} onChange={setAutoRefresh} />
            </Space>
          </Tooltip>
          <Button
            icon={<ReloadOutlined />}
            onClick={() => void logsQuery.refetch()}
            loading={logsQuery.isFetching}
          />
        </Space>
      }
    >
      <Table
        rowKey={(r, i) => `${i}-${String(r.ts ?? '')}`}
        size="small"
        loading={logsQuery.isLoading}
        dataSource={items}
        pagination={false}
        scroll={{ x: 900 }}
        columns={[
          { title: 'Время', width: 170, render: (_, r) => <Typography.Text code>{String(r.ts ?? '')}</Typography.Text> },
          {
            title: 'Уровень',
            width: 80,
            render: (_, r) => <Tag color={levelColor[String(r.level)] ?? 'default'}>{String(r.level ?? '')}</Tag>,
          },
          { title: 'Событие', width: 130, render: (_, r) => String(r.event ?? r.message ?? '') },
          {
            title: 'Детали',
            render: (_, r) => {
              const parts: string[] = [];
              if (r.username) parts.push(`user=${r.username}`);
              if (r.result) parts.push(`result=${r.result}`);
              if (r.method) parts.push(`${r.method} ${r.path ?? ''} ${r.status ?? ''}`);
              if (r.ip) parts.push(`ip=${r.ip}`);
              if (r.error) parts.push(`err=${String(r.error)}`);
              if (r.removed) parts.push(`removed=${(r.removed as string[]).join(',')}`);
              if (r.duration) parts.push(`${r.duration}мс`);
              return <span style={{ fontSize: 12 }}>{parts.join(' · ') || String(r.message ?? '')}</span>;
            },
          },
          { title: 'request_id', width: 160, render: (_, r) => <Typography.Text code style={{ fontSize: 11 }}>{String(r.request_id ?? '')}</Typography.Text> },
        ]}
      />
      <div style={{ marginTop: 12, display: 'flex', gap: 8 }}>
        <Button size="small" disabled={offset === 0} onClick={() => setOffset(0)}>
          В начало
        </Button>
        <Button size="small" disabled={!logsQuery.data?.next_offset} onClick={() => setOffset(logsQuery.data?.next_offset ?? 0)}>
          Далее
        </Button>
        <Typography.Text type="secondary" style={{ fontSize: 12, alignSelf: 'center' }}>
          строк: {items.length}{logsQuery.data?.next_offset ? '+' : ''}
        </Typography.Text>
      </div>
    </Card>
  );
}
