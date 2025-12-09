export const DANGEROUS_PORTS = [22, 3389, 3306, 5432, 1433, 6379, 27017, 5984] as const;

export const CRITICAL_PORT_MAP = new Map<number, string>([
  [22, 'SSH'],
  [3389, 'RDP'],
  [3306, 'MySQL'],
  [5432, 'PostgreSQL'],
  [1433, 'SQL Server'],
  [6379, 'Redis'],
  [27017, 'MongoDB'],
  [5984, 'CouchDB'],
]);

export const PORT_RANGE_THRESHOLD = 100;
export const EXPOSED_PORTS_MEDIUM_THRESHOLD = 5;

export type DangerousPort = (typeof DANGEROUS_PORTS)[number];
