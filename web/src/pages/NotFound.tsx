import { Link } from "react-router-dom";
import { Empty } from "../components/ui.tsx";

export function NotFound() {
  return (
    <Empty title="没有这个页面" icon="?">
      <Link to="/">回到概览</Link>
    </Empty>
  );
}
