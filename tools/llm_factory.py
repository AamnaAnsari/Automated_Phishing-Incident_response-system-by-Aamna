"""Builds the chat model for the provider chosen in .env (groq | gemini | openai)."""
from config import Config

DEFAULT_MODELS = {
    "groq": "llama-3.3-70b-versatile",
    "gemini": "gemini-2.5-flash",
    "openai": "gpt-4o-mini",
}


def get_llm():
    provider, key = Config.LLM_PROVIDER.lower().strip(), Config.LLM_API_KEY
    if not key:
        raise RuntimeError("LLM_API_KEY is empty. Add it to your .env file.")
    model = Config.LLM_MODEL or DEFAULT_MODELS.get(provider)

    if provider == "groq":
        from langchain_groq import ChatGroq
        return ChatGroq(model=model, api_key=key, temperature=0)
    if provider == "gemini":
        from langchain_google_genai import ChatGoogleGenerativeAI
        return ChatGoogleGenerativeAI(model=model, google_api_key=key, temperature=0)
    if provider == "openai":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(model=model, api_key=key, temperature=0)
    raise ValueError(f"Unknown LLM_PROVIDER '{provider}'. Use groq, gemini or openai.")
