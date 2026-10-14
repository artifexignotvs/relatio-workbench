import React from "react";
import ReactDOM from "react-dom/client";
import SecurityWorkspace from "./features/security-workspace/SecurityWorkspace";
import "./features/security-workspace/security-workspace.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <SecurityWorkspace />
  </React.StrictMode>,
);
