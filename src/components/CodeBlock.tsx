interface CodeBlockProps {
  badCode: string;
  fixedCode: string;
  line: number;
}

const CodeBlock = ({ badCode, fixedCode, line }: CodeBlockProps) => {
  return (
    <div className="bg-[#010409] border-t border-border p-4 font-mono text-xs leading-7 overflow-x-auto">
      <div className="flex gap-4 bg-severity-critical-dim -mx-4 px-4">
        <span className="text-severity-critical select-none min-w-[24px] text-right">{line}</span>
        <span className="text-severity-critical">{badCode}</span>
      </div>
      <div className="flex gap-4 bg-primary/5 -mx-4 px-4">
        <span className="text-primary select-none min-w-[24px] text-right">{line}</span>
        <span className="text-primary">{fixedCode}</span>
      </div>
    </div>
  );
};

export default CodeBlock;
