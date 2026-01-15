"use client";

import { useState } from "react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

const demoThreats: Record<string, string> = {
  "https://github.com/GSA/auctions_api": "API key found: apiKey: 0aYAx2eY37dkfjqsrrZ53SSCkY1yY2kRYGvY27rv`",
  "https://github.com/lut0pia/raccoon": "Unsafe dependency detected: `eval(require('fs').readFileSync('config.json'))`",
};

export default function RepoScanner() {
  const [repoUrl, setRepoUrl] = useState("");
  const [scanResults, setScanResults] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleScan = () => {
    setLoading(true);
    setScanResults(null);
    const randomDelay = Math.floor(Math.random() * (10000 - 5000 + 1)) + 5000; // Random delay between 5-10 seconds

    setTimeout(() => {
      if (demoThreats[repoUrl]) {
        setScanResults(demoThreats[repoUrl]);
      } else {
        setScanResults("No threats detected.");
      }
      setLoading(false);
    }, randomDelay);
  };

  return (
    <div className="min-h-screen flex flex-col items-center justify-center p-4">
      <h1 className="text-3xl font-bold mb-6 text-center">GitGuard - GitHub Repository Threat Scanner</h1>
      <Card className="w-full max-w-lg p-6 rounded-2xl shadow-lg">
        <CardContent className="space-y-4">
          <label className="block text-lg font-medium">Scan a Repository</label>
          <Input
            type="text"
            placeholder="https://github.com/user/repo"
            value={repoUrl}
            onChange={(e) => setRepoUrl(e.target.value)}
            className="w-full p-2 rounded-lg border border-border focus:ring focus:ring-ring"
          />
          <Button
            onClick={handleScan}
            disabled={loading}
            className="w-full bg-primary text-primary-foreground hover:bg-primary/90 font-bold py-2 px-4 rounded-lg"
          >
            {loading ? "Scanning..." : "Scan Repository"}
          </Button>
        </CardContent>
      </Card>
      <div className="mt-6 w-full max-w-lg p-6 rounded-2xl shadow-lg border">
        <h2 className="text-xl font-semibold">Scan Results</h2>
        <div className="mt-4">
          {loading ? (
            <div className="flex items-center justify-center">
              <div className="w-6 h-6 border-4 border-t-transparent border-gray-500 rounded-full animate-spin"></div>
            </div>
          ) : (
            scanResults ? <pre className="bg-gray-800 text-red-400 p-2 rounded-lg overflow-auto">{scanResults}</pre> : "No results to display."
          )}
        </div>
      </div>
      <footer className="mt-6 text-sm text-muted-foreground">© 2025 GitGuard. All Rights Reserved.</footer>
    </div>
  );
}
