from enum import Enum
VICUNA_PATH = "/home/pchao/vicuna-13b-v1.5"
LLAMA_PATH = "/home/pchao/Llama-2-7b-chat-hf"

ATTACK_TEMP = 1
TARGET_TEMP = 0
ATTACK_TOP_P = 0.9
TARGET_TOP_P = 1


## MODEL PARAMETERS ##
class Model(Enum):
    vicuna = "vicuna-13b-v1.5"
    llama_2 = "llama-2-7b-chat-hf"
    vicuna_7b_local = "vicuna-7b-v1.5"
    phi3_local = "phi-3-mini-4k-instruct"
    gpt_3_5 = "gpt-3.5-turbo-1106"
    gpt_4_base = "gpt-4"
    gpt_4 = "gpt-4-0125-preview"
    gpt_4_1 = "gpt-4.1-2025-04-14"
    gpt_5_2 = "gpt-5.2"
    claude_1 = "claude-instant-1.2"
    claude_2 = "claude-2.1"
    claude_3_haiku = "claude-3-haiku-20240307"
    claude_3_5_sonnet = "claude-3-5-sonnet-20241022"
    claude_3_5_haiku = "claude-3-5-haiku-20241022"
    claude_opus = "claude-3-opus-20250219"
    claude_sonnet_4_6 = "claude-sonnet-4-6"
    claude_opus_4_6 = "claude-opus-4-6"
    claude_haiku_4_5 = "claude-haiku-4-5-20251001"
    gemini = "gemini-pro"
    gemini_2_5_pro = "gemini-2.5-pro"
    gemini_2_5_flash = "gemini-2.5-flash"
    gemini_2_5_flash_lite = "gemini-2.5-flash-lite"
    gemini_3_flash = "gemini-3-flash"
    gemini_3_pro = "gemini-3-pro"
    mixtral = "mixtral"
    sonar = "sonar-pro"
    sonar_chat = "sonar"
    # NVIDIA NIM Models (Free tier: 1,000 calls/day)
    # Verified active on build.nvidia.com as of 2026-05.
    # Deprecated NIM endpoints (llama3-8b, llama3-70b, codellama-70b,
    # phi-3-mini-4k, mistral-7b-instruct (v0.1), nemotron-4-340b) have been
    # replaced by their current successors below.
    # Liveness verified by probing inference endpoint on 2026-05-14 (catalog
    # presence does not guarantee callability — qwen2.5-coder-32b and 7 others
    # were retired from this account between 2026-05-09 and 2026-05-14).
    nvidia_llama31_8b = "nvidia-llama-3.1-8b-instruct"
    nvidia_llama33_70b = "nvidia-llama-3.3-70b-instruct"
    nvidia_mixtral_8x7b = "nvidia-mixtral-8x7b-instruct"
    nvidia_qwen3_coder_480b = "nvidia-qwen3-coder-480b"   # 480B MoE (35B active) — only live code specialist
    nvidia_llama_guard_4_12b = "nvidia-llama-guard-4-12b" # safety classifier (safe/unsafe), NOT a 1-10 scorer
    # Lightweight (<= 12B params) — fast attackers/judges
    nvidia_llama32_1b = "nvidia-llama-3.2-1b-instruct"
    nvidia_llama32_3b = "nvidia-llama-3.2-3b-instruct"
    nvidia_gemma2_2b = "nvidia-gemma-2-2b-it"
    nvidia_gemma3_12b = "nvidia-gemma-3-12b-it"
    nvidia_gemma3n_e2b = "nvidia-gemma-3n-e2b-it"
    nvidia_phi4_mini = "nvidia-phi-4-mini-instruct"
    nvidia_nemotron_mini_4b = "nvidia-nemotron-mini-4b-instruct"
    nvidia_nemotron_nano_8b = "nvidia-llama-3.1-nemotron-nano-8b"
    # Mid-size (12-30B) — added 2026-05-14, verified live
    nvidia_ministral_14b = "nvidia-ministral-14b-instruct"
    # Large flagship (70-700B+) — high-quality, commercial-comparable
    nvidia_llama31_70b = "nvidia-llama-3.1-70b-instruct"
    nvidia_llama4_maverick = "nvidia-llama-4-maverick-17b"      # 17B active × 128 experts MoE
    nvidia_mistral_medium_3_5 = "nvidia-mistral-medium-3.5-128b"
    nvidia_mistral_large_3 = "nvidia-mistral-large-3-675b"      # 675B, slow (~30-60s inference)
    nvidia_mistral_small_4 = "nvidia-mistral-small-4-119b"
    nvidia_mixtral_8x22b = "nvidia-mixtral-8x22b-instruct"
    nvidia_nemotron_super_49b = "nvidia-llama-3.3-nemotron-super-49b"
    nvidia_nemotron3_super_120b = "nvidia-nemotron-3-super-120b"  # 120B MoE (12B active)
    nvidia_qwen3_next_80b = "nvidia-qwen3-next-80b-instruct"      # 80B MoE (3B active)
    nvidia_qwen3_next_80b_thinking = "nvidia-qwen3-next-80b-thinking"
    nvidia_dracarys_llama31_70b = "nvidia-dracarys-llama-3.1-70b" # coder fine-tune of Llama-3.1-70B
    # DeepSeek (transient availability on this account — preflight will catch)
    nvidia_deepseek_v4_pro = "nvidia-deepseek-v4-pro"             # flagship reasoning
    nvidia_deepseek_v4_flash = "nvidia-deepseek-v4-flash"         # smaller flagship
    # --- Removed 2026-05-14 (confirmed 404/410 on inference probe) ---
    # nvidia_mistral_7b_v3              = "nvidia-mistral-7b-instruct-v0.3"
    # nvidia_qwen25_coder_32b           = "nvidia-qwen25-coder-32b"           # EOL 2026-05-12; use nvidia_qwen3_coder_480b instead
    # nvidia_nemotron_70b               = "nvidia-llama-3.1-nemotron-70b-instruct"
    # nv_mistral_nemo_12b               = "nvidia-mistral-nemo-12b-instruct"
    # nvidia_mistral_nemo_minitron_8b   = "nvidia-mistral-nemo-minitron-8b"
    # nvidia_nemotron_nano_9b_v2        = "nvidia-nemotron-nano-9b-v2"
    # nvidia_granite3_8b                = "nvidia-granite-3.0-8b-instruct"
    # nvidia_granite3_3b_moe            = "nvidia-granite-3.0-3b-a800m-instruct"

MODEL_NAMES = [model.value for model in Model]


HF_MODEL_NAMES: dict[Model, str] = {
    Model.llama_2: "meta-llama/Llama-2-7b-chat-hf",
    Model.vicuna: "lmsys/vicuna-13b-v1.5",
    Model.mixtral: "mistralai/Mixtral-8x7B-Instruct-v0.1"
}

TOGETHER_MODEL_NAMES: dict[Model, str] = {
    Model.llama_2: "together_ai/togethercomputer/llama-2-7b-chat",
    Model.vicuna: "together_ai/lmsys/vicuna-13b-v1.5",
    Model.mixtral: "together_ai/mistralai/Mixtral-8x7B-Instruct-v0.1"
}

NVIDIA_MODEL_NAMES: dict[Model, str] = {
    # All entries verified callable on 2026-05-14 via inference probe
    # (preflight.py replicates this check before every run).
    Model.nvidia_llama31_8b: "nvidia_nim/meta/llama-3.1-8b-instruct",
    Model.nvidia_llama33_70b: "nvidia_nim/meta/llama-3.3-70b-instruct",
    Model.nvidia_mixtral_8x7b: "nvidia_nim/mistralai/mixtral-8x7b-instruct-v0.1",
    Model.nvidia_qwen3_coder_480b: "nvidia_nim/qwen/qwen3-coder-480b-a35b-instruct",
    Model.nvidia_llama_guard_4_12b: "nvidia_nim/meta/llama-guard-4-12b",
    # Lightweight (<= 12B)
    Model.nvidia_llama32_1b: "nvidia_nim/meta/llama-3.2-1b-instruct",
    Model.nvidia_llama32_3b: "nvidia_nim/meta/llama-3.2-3b-instruct",
    Model.nvidia_gemma2_2b: "nvidia_nim/google/gemma-2-2b-it",
    Model.nvidia_gemma3_12b: "nvidia_nim/google/gemma-3-12b-it",
    Model.nvidia_gemma3n_e2b: "nvidia_nim/google/gemma-3n-e2b-it",
    Model.nvidia_phi4_mini: "nvidia_nim/microsoft/phi-4-mini-instruct",
    Model.nvidia_nemotron_mini_4b: "nvidia_nim/nvidia/nemotron-mini-4b-instruct",
    Model.nvidia_nemotron_nano_8b: "nvidia_nim/nvidia/llama-3.1-nemotron-nano-8b-v1",
    # Mid-size and large flagship (verified live on 2026-05-14)
    Model.nvidia_ministral_14b: "nvidia_nim/mistralai/ministral-14b-instruct-2512",
    Model.nvidia_llama31_70b: "nvidia_nim/meta/llama-3.1-70b-instruct",
    Model.nvidia_llama4_maverick: "nvidia_nim/meta/llama-4-maverick-17b-128e-instruct",
    Model.nvidia_mistral_medium_3_5: "nvidia_nim/mistralai/mistral-medium-3.5-128b",
    Model.nvidia_mistral_large_3: "nvidia_nim/mistralai/mistral-large-3-675b-instruct-2512",
    Model.nvidia_mistral_small_4: "nvidia_nim/mistralai/mistral-small-4-119b-2603",
    Model.nvidia_mixtral_8x22b: "nvidia_nim/mistralai/mixtral-8x22b-instruct-v0.1",
    Model.nvidia_nemotron_super_49b: "nvidia_nim/nvidia/llama-3.3-nemotron-super-49b-v1",
    Model.nvidia_nemotron3_super_120b: "nvidia_nim/nvidia/nemotron-3-super-120b-a12b",
    Model.nvidia_qwen3_next_80b: "nvidia_nim/qwen/qwen3-next-80b-a3b-instruct",
    Model.nvidia_qwen3_next_80b_thinking: "nvidia_nim/qwen/qwen3-next-80b-a3b-thinking",
    Model.nvidia_dracarys_llama31_70b: "nvidia_nim/abacusai/dracarys-llama-3.1-70b-instruct",
    # DeepSeek (transient availability — preflight.py blocks if not callable)
    Model.nvidia_deepseek_v4_pro: "nvidia_nim/deepseek-ai/deepseek-v4-pro",
    Model.nvidia_deepseek_v4_flash: "nvidia_nim/deepseek-ai/deepseek-v4-flash",
}

FASTCHAT_TEMPLATE_NAMES: dict[Model, str] = {
    Model.gpt_3_5: "gpt-3.5-turbo",
    Model.gpt_4_base: "gpt-4",
    Model.gpt_4: "gpt-4",
    Model.gpt_4_1: "gpt-4.1",
    Model.gpt_5_2: "gpt-5.2",
    Model.claude_1: "zero_shot",
    Model.claude_2: "zero_shot",
    Model.claude_3_haiku: "zero_shot",
    Model.claude_3_5_sonnet: "zero_shot",
    Model.claude_3_5_haiku: "zero_shot",
    Model.claude_opus: "zero_shot",
    Model.claude_sonnet_4_6: "zero_shot",
    Model.claude_opus_4_6: "zero_shot",
    Model.claude_haiku_4_5: "zero_shot",
    Model.gemini: "gemini-pro",
    Model.gemini_2_5_pro: "gemini-2.5-pro",
    Model.gemini_2_5_flash: "gemini-2.5-flash",
    Model.gemini_2_5_flash_lite: "gemini-2.5-flash-lite",
    Model.gemini_3_flash: "gemini-3-flash",
    Model.gemini_3_pro: "gemini-3-pro",
    Model.vicuna: "vicuna_v1.1",
    Model.llama_2: "llama-2-7b-chat-hf",
    Model.vicuna_7b_local: "vicuna_v1.1",
    Model.phi3_local: "zero_shot",
    Model.mixtral: "mixtral",
    Model.sonar: "sonar-pro",
    Model.sonar_chat: "sonar",
    # NVIDIA NIM Models
    Model.nvidia_llama31_8b: "llama-3",
    Model.nvidia_llama33_70b: "llama-3",
    Model.nvidia_mixtral_8x7b: "mixtral",
    Model.nvidia_qwen3_coder_480b: "qwen",
    Model.nvidia_llama_guard_4_12b: "llama-3",
    # Lightweight
    Model.nvidia_llama32_1b: "llama-3",
    Model.nvidia_llama32_3b: "llama-3",
    Model.nvidia_gemma2_2b: "gemma",
    Model.nvidia_gemma3_12b: "gemma",
    Model.nvidia_gemma3n_e2b: "gemma",
    Model.nvidia_phi4_mini: "phi-3",
    Model.nvidia_nemotron_mini_4b: "zero_shot",
    Model.nvidia_nemotron_nano_8b: "llama-3",
    # Mid and large additions
    Model.nvidia_ministral_14b: "mistral",
    Model.nvidia_llama31_70b: "llama-3",
    Model.nvidia_llama4_maverick: "llama-3",
    Model.nvidia_mistral_medium_3_5: "mistral",
    Model.nvidia_mistral_large_3: "mistral",
    Model.nvidia_mistral_small_4: "mistral",
    Model.nvidia_mixtral_8x22b: "mixtral",
    Model.nvidia_nemotron_super_49b: "llama-3",
    Model.nvidia_nemotron3_super_120b: "zero_shot",
    Model.nvidia_qwen3_next_80b: "qwen",
    Model.nvidia_qwen3_next_80b_thinking: "qwen",
    Model.nvidia_dracarys_llama31_70b: "llama-3",
    Model.nvidia_deepseek_v4_pro: "zero_shot",
    Model.nvidia_deepseek_v4_flash: "zero_shot",
}

API_KEY_NAMES: dict[Model, str] = {
    Model.gpt_3_5:  "OPENAI_API_KEY",
    Model.gpt_4_base: "OPENAI_API_KEY",
    Model.gpt_4:    "OPENAI_API_KEY",
    Model.gpt_4_1:  "OPENAI_API_KEY",
    Model.gpt_5_2:  "OPENAI_API_KEY",
    Model.claude_1: "ANTHROPIC_API_KEY",
    Model.claude_2: "ANTHROPIC_API_KEY",
    Model.claude_3_haiku: "ANTHROPIC_API_KEY",
    Model.claude_3_5_sonnet: "ANTHROPIC_API_KEY",
    Model.claude_3_5_haiku: "ANTHROPIC_API_KEY",
    Model.claude_opus: "ANTHROPIC_API_KEY",
    Model.claude_sonnet_4_6: "ANTHROPIC_API_KEY",
    Model.claude_opus_4_6: "ANTHROPIC_API_KEY",
    Model.claude_haiku_4_5: "ANTHROPIC_API_KEY",
    Model.gemini:   "GOOGLE_API_KEY",
    Model.gemini_2_5_pro: "GOOGLE_API_KEY",
    Model.gemini_2_5_flash: "GOOGLE_API_KEY",
    Model.gemini_2_5_flash_lite: "GOOGLE_API_KEY",
    Model.gemini_3_flash: "GOOGLE_API_KEY",
    Model.gemini_3_pro: "GOOGLE_API_KEY",
    Model.vicuna:   "TOGETHER_API_KEY",
    Model.llama_2:  "TOGETHER_API_KEY",
    Model.mixtral:  "TOGETHER_API_KEY",
    Model.sonar:    "PERPLEXITYAI_API_KEY",
    Model.sonar_chat: "PERPLEXITYAI_API_KEY",
    Model.vicuna_7b_local: "LMSTUDIO_API_KEY",
    Model.phi3_local: "LMSTUDIO_API_KEY",
    # NVIDIA NIM Models - all use the same API key
    Model.nvidia_llama31_8b: "NVIDIA_NIM_API_KEY",
    Model.nvidia_llama33_70b: "NVIDIA_NIM_API_KEY",
    Model.nvidia_mixtral_8x7b: "NVIDIA_NIM_API_KEY",
    Model.nvidia_qwen3_coder_480b: "NVIDIA_NIM_API_KEY",
    Model.nvidia_llama_guard_4_12b: "NVIDIA_NIM_API_KEY",
    Model.nvidia_llama32_1b: "NVIDIA_NIM_API_KEY",
    Model.nvidia_llama32_3b: "NVIDIA_NIM_API_KEY",
    Model.nvidia_gemma2_2b: "NVIDIA_NIM_API_KEY",
    Model.nvidia_gemma3_12b: "NVIDIA_NIM_API_KEY",
    Model.nvidia_gemma3n_e2b: "NVIDIA_NIM_API_KEY",
    Model.nvidia_phi4_mini: "NVIDIA_NIM_API_KEY",
    Model.nvidia_nemotron_mini_4b: "NVIDIA_NIM_API_KEY",
    Model.nvidia_nemotron_nano_8b: "NVIDIA_NIM_API_KEY",
    Model.nvidia_ministral_14b: "NVIDIA_NIM_API_KEY",
    Model.nvidia_llama31_70b: "NVIDIA_NIM_API_KEY",
    Model.nvidia_llama4_maverick: "NVIDIA_NIM_API_KEY",
    Model.nvidia_mistral_medium_3_5: "NVIDIA_NIM_API_KEY",
    Model.nvidia_mistral_large_3: "NVIDIA_NIM_API_KEY",
    Model.nvidia_mistral_small_4: "NVIDIA_NIM_API_KEY",
    Model.nvidia_mixtral_8x22b: "NVIDIA_NIM_API_KEY",
    Model.nvidia_nemotron_super_49b: "NVIDIA_NIM_API_KEY",
    Model.nvidia_nemotron3_super_120b: "NVIDIA_NIM_API_KEY",
    Model.nvidia_qwen3_next_80b: "NVIDIA_NIM_API_KEY",
    Model.nvidia_qwen3_next_80b_thinking: "NVIDIA_NIM_API_KEY",
    Model.nvidia_dracarys_llama31_70b: "NVIDIA_NIM_API_KEY",
    Model.nvidia_deepseek_v4_pro: "NVIDIA_NIM_API_KEY",
    Model.nvidia_deepseek_v4_flash: "NVIDIA_NIM_API_KEY",
}

LOCAL_MODEL_API_BASES: dict[Model, str] = {
    Model.vicuna_7b_local: "http://127.0.0.1:1234/v1",
    Model.phi3_local: "http://127.0.0.1:1234/v1",
}

LITELLM_TEMPLATES: dict[Model, dict] = {
    Model.vicuna: {"roles":{
                    "system": {"pre_message": "", "post_message": " "},
                    "user": {"pre_message": "USER: ", "post_message": " ASSISTANT:"},
                    "assistant": {
                        "pre_message": "",
                        "post_message": "",
                    },
                },
                "post_message":"</s>",
                "initial_prompt_value" : "",
                "eos_tokens": ["</s>"]         
                },
    Model.llama_2: {"roles":{
                    "system": {"pre_message": "[INST] <<SYS>>\n", "post_message": "\n<</SYS>>\n\n"},
                    "user": {"pre_message": "", "post_message": " [/INST]"},
                    "assistant": {"pre_message": "", "post_message": ""},
                },
                "post_message" : " </s><s>",
                "initial_prompt_value" : "",
                "eos_tokens" :  ["</s>", "[/INST]"]  
            },
    Model.mixtral: {"roles":{
                    "system": {
                        "pre_message": "[INST] ",
                        "post_message": " [/INST]"
                    },
                    "user": { 
                        "pre_message": "[INST] ",
                        "post_message": " [/INST]"
                    }, 
                    "assistant": {
                        "pre_message": " ",
                        "post_message": "",
                    }
                },
                "post_message": "</s>",
                "initial_prompt_value" : "<s>",
                "eos_tokens": ["</s>", "[/INST]"]
    }
}
