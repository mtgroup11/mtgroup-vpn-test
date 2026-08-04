import type { Metadata } from 'next';
import '../../styles.css';

export const metadata: Metadata = {
  title: 'XDP-Spectre NOC',
  description: 'Singularity Edition',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
