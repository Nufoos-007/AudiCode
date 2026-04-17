import type { VercelRequest, VercelResponse } from "@vercel/node";

export default async function handler(request: VercelRequest, response: VercelResponse) {
  if (request.method !== "POST") {
    return response.status(405).json({ error: "Method not allowed" });
  }

  const { title, description, category, code, fix } = request.body;

  if (!title) {
    return response.status(400).json({ error: "Missing title" });
  }

  const apiKey = process.env.GEMINI_API_KEY;

  if (!apiKey || apiKey === "your-gemini-api-key-here") {
    return response.status(503).json({ 
      error: "AI explanation service not configured",
      explanation: "AI explanations are not available. The fix suggestion is: " + (fix || "Review and fix this code manually.")
    });
  }

  try {
    const prompt = `You are a security expert explaining a code vulnerability. 

Vulnerability Details:
- Title: ${title}
- Description: ${description}
- Category: ${category}
- Code: ${code}
- Suggested Fix: ${fix || "None"}

Write a brief, clear explanation (2-3 sentences max) that helps a developer understand:
1. Why this is dangerous
2. How to fix it

Keep it concise and actionable.`;

    const geminiResponse = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: {
            temperature: 0.7,
            maxOutputTokens: 256,
          },
        }),
      }
    );

    if (!geminiResponse.ok) {
      throw new Error(`Gemini API error: ${geminiResponse.status}`);
    }

    const data = await geminiResponse.json();
    const explanation = data?.candidates?.[0]?.content?.parts?.[0]?.text || 
      "AI explanation unavailable. Please review the fix suggestion.";

    return response.status(200).json({ explanation });
  } catch (error: any) {
    console.error("AI explain error:", error.message);
    return response.status(500).json({ 
      error: "Failed to get AI explanation",
      explanation: "Could not generate explanation. " + (fix || "Please review and fix manually.")
    });
  }
}