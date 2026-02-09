import os
import litellm
from config import TOGETHER_MODEL_NAMES, LITELLM_TEMPLATES, API_KEY_NAMES, Model
from loggers import logger
from common import get_api_key
import time
import warnings

# Suppress verbose LiteLLM logging
litellm.suppress_debug_info = True
litellm.set_verbose = False

# Suppress NumPy warnings about division
warnings.filterwarnings('ignore', category=RuntimeWarning, message='.*invalid value encountered in scalar divide.*')


class LanguageModel():
    def __init__(self, model_name):
        self.model_name = Model(model_name)

    def batched_generate(self, prompts_list: list, max_n_tokens: int, temperature: float):
        """
        Generates responses for a batch of prompts using a language model.
        """
        raise NotImplementedError


class PerplexityModel(LanguageModel):
    """Perplexity AI model wrapper - compatible with APILiteLLM interface"""

    API_RETRY_SLEEP = 10
    API_ERROR_OUTPUT = "ERROR: API CALL FAILED."
    API_QUERY_SLEEP = 1
    API_MAX_RETRY = 5
    API_TIMEOUT = 20

    def __init__(self, model_name='sonar-pro'):
        # Initialize parent with model name
        if isinstance(model_name, str):
            try:
                self.model_name = Model(model_name)
            except ValueError:
                # If it's not a standard Model enum value, use it as-is
                self.model_name_str = model_name
                self.model_name = None
        else:
            self.model_name = model_name

        # Get API key
        self.api_key = os.environ.get('PERPLEXITYAI_API_KEY')
        if not self.api_key:
            raise ValueError("PERPLEXITYAI_API_KEY not set in environment")

        self.API_URL = "https://api.perplexity.ai/chat/completions"
        self.use_open_source_model = False
        self.eos_tokens = []
        self.post_message = ""

    def get_response(self, messages, max_tokens=150, temperature=1.0):
        """Get single response from Perplexity"""
        import requests

        # Format messages if needed
        if isinstance(messages, str):
            messages = [{"role": "user", "content": messages}]
        elif isinstance(messages, list) and messages and isinstance(messages[0], str):
            messages = [{"role": "user", "content": msg} for msg in messages]

        # Get actual model name
        model_name = getattr(self, 'model_name_str', 'sonar-pro')
        if self.model_name:
            model_name = self.model_name.value

        response = requests.post(
            self.API_URL,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            },
            json={
                "model": model_name,
                "messages": messages,
                "max_tokens": max_tokens,
                "temperature": temperature
            },
            timeout=self.API_TIMEOUT
        )

        if response.status_code != 200:
            logger.error(f"Perplexity API error: {response.text}")
            raise Exception(f"Perplexity API error: {response.status_code} - {response.text}")

        return response.json()["choices"][0]["message"]["content"]

    def batched_generate(self, convs_list: list[list[dict]],
                        max_n_tokens: int = 150,
                        temperature: float = 1.0,
                        top_p: float = 1.0,
                        extra_eos_tokens: list[str] = None) -> list[str]:
        """Generate responses for multiple conversations/prompts with retry logic"""
        import requests

        # Get actual model name
        model_name = getattr(self, 'model_name_str', 'sonar-pro')
        if self.model_name:
            model_name = self.model_name.value

        responses = []

        for attempt in range(self.API_MAX_RETRY):
            try:
                batch_responses = []
                for conv_messages in convs_list:
                    response = requests.post(
                        self.API_URL,
                        headers={
                            "Authorization": f"Bearer {self.api_key}",
                            "Content-Type": "application/json"
                        },
                        json={
                            "model": model_name,
                            "messages": conv_messages,
                            "max_tokens": max_n_tokens,
                            "temperature": temperature,
                            "top_p": top_p
                        },
                        timeout=self.API_TIMEOUT
                    )

                    if response.status_code != 200:
                        logger.error(f"Perplexity API error: {response.text}")
                        batch_responses.append(self.API_ERROR_OUTPUT)
                    else:
                        try:
                            content = response.json()["choices"][0]["message"]["content"]
                            batch_responses.append(content)
                        except (KeyError, IndexError) as e:
                            logger.error(f"Failed to parse Perplexity response: {e}")
                            batch_responses.append(self.API_ERROR_OUTPUT)

                    # Rate limiting
                    time.sleep(self.API_QUERY_SLEEP)

                return batch_responses

            except requests.exceptions.RequestException as e:
                if attempt < self.API_MAX_RETRY - 1:
                    wait_time = 2 ** attempt
                    logger.warning(f"Perplexity API retry {attempt + 1}/{self.API_MAX_RETRY} in {wait_time}s: {e}")
                    time.sleep(wait_time)
                else:
                    logger.error(f"Perplexity API failed after {self.API_MAX_RETRY} attempts")
                    return [self.API_ERROR_OUTPUT] * len(convs_list)

class APILiteLLM(LanguageModel):
    API_RETRY_SLEEP = 10
    API_ERROR_OUTPUT = "ERROR: API CALL FAILED."
    API_QUERY_SLEEP = 1
    API_MAX_RETRY = 5
    API_TIMEOUT = 20

    def __init__(self, model_name):
        super().__init__(model_name)
        self.api_key = get_api_key(self.model_name)
        self.litellm_model_name = self.get_litellm_model_name(self.model_name)
        litellm.drop_params=True
        self.set_eos_tokens(self.model_name)
        
    def get_litellm_model_name(self, model_name):
        if model_name in TOGETHER_MODEL_NAMES:
            litellm_name = TOGETHER_MODEL_NAMES[model_name]
            self.use_open_source_model = True
        else:
            self.use_open_source_model =  False
            #if self.use_open_source_model:
                # Output warning, there should be a TogetherAI model name
                #logger.warning(f"Warning: No TogetherAI model name for {model_name}.")
            litellm_name = model_name.value 
        return litellm_name
    
    def set_eos_tokens(self, model_name):
        if self.use_open_source_model:
            self.eos_tokens = LITELLM_TEMPLATES[model_name]["eos_tokens"]     
        else:
            self.eos_tokens = []

    def _update_prompt_template(self):
        # We manually add the post_message later if we want to seed the model response
        if self.model_name in LITELLM_TEMPLATES:
            litellm.register_prompt_template(
                initial_prompt_value=LITELLM_TEMPLATES[self.model_name]["initial_prompt_value"],
                model=self.litellm_model_name,
                roles=LITELLM_TEMPLATES[self.model_name]["roles"]
            )
            self.post_message = LITELLM_TEMPLATES[self.model_name]["post_message"]
        else:
            self.post_message = ""

    def batched_generate(self, convs_list: list[list[dict]],
                         max_n_tokens: int,
                         temperature: float,
                         top_p: float,
                         extra_eos_tokens: list[str] = None) -> list[str]:

        eos_tokens = self.eos_tokens.copy()  # Make a copy to avoid modifying the original

        if extra_eos_tokens:
            eos_tokens.extend(extra_eos_tokens)

        # CRITICAL FIX: OpenAI only allows max 4 stop sequences
        if len(eos_tokens) > 4:
            print(f"[WARNING] Truncating stop tokens from {len(eos_tokens)} to 4 (OpenAI limit)")
            eos_tokens = eos_tokens[:4]

        if self.use_open_source_model:
            self._update_prompt_template()

        # Determine correct parameters for newer OpenAI models
        # GPT-4.1+, GPT-5.2+: use max_completion_tokens, no stop parameter
        is_new_openai_model = any([
            'gpt-5' in self.litellm_model_name.lower(),
            'gpt-4.1' in self.litellm_model_name.lower(),
        ])

        # Build completion parameters
        completion_params = {
            'model': self.litellm_model_name,
            'messages': convs_list,
            'api_key': self.api_key,
            'temperature': temperature,
            'top_p': top_p,
            'num_retries': self.API_MAX_RETRY,
            'seed': 0,
        }

        # Add stop sequences only for models that support them
        if not is_new_openai_model:
            completion_params['stop'] = eos_tokens

        # Add correct max tokens parameter based on model
        if is_new_openai_model:
            completion_params['max_completion_tokens'] = max_n_tokens
        else:
            completion_params['max_tokens'] = max_n_tokens

        # ADDED: Retry logic with exponential backoff
        max_retries = 3
        for attempt in range(max_retries):
            try:
                outputs = litellm.batch_completion(**completion_params)
                break  # Success, exit retry loop
            except Exception as e:
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt  # Exponential backoff: 1s, 2s, 4s
                    print(f"[API RETRY] Attempt {attempt + 1} failed, retrying in {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    print(f"[API FATAL] All retry attempts failed: {e}")
                    # Return default responses for all inputs
                    return ["I apologize, but I cannot assist with that request."] * len(convs_list)

        # FIXED ERROR HANDLING
        responses = []
        for i, output in enumerate(outputs):
            try:
                response = None
                # Handle ModelResponse objects from litellm
                if hasattr(output, 'choices') and hasattr(output, '__dict__'):
                    # It's a ModelResponse object, access as attribute
                    response = output.choices[0].message.content
                elif isinstance(output, dict) and "choices" in output:
                    # It's a dictionary response
                    response = output["choices"][0]["message"]["content"]
                else:
                    # Handle error objects
                    print(f"[API ERROR] Request {i} failed: {type(output).__name__}")
                    if hasattr(output, 'message'):
                        print(f"  Error message: {output.message}")
                    response = "I apologize, but I cannot assist with that request."

                # Check for empty/None responses
                if response is None or (isinstance(response, str) and response.strip() == ""):
                    print(f"[API WARNING] Request {i} returned empty response. Full output: {output}")
                    response = "I apologize, but I cannot assist with that request."

                responses.append(response)
            except (TypeError, KeyError, AttributeError, IndexError) as e:
                print(f"[PARSE ERROR] Request {i} failed to parse: {e}")
                responses.append("I apologize, but I cannot assist with that request.")

        return responses

    # def batched_generate(self, convs_list: list[list[dict]],
    #                      max_n_tokens: int,
    #                      temperature: float,
    #                      top_p: float,
    #                      extra_eos_tokens: list[str] = None) -> list[str]:
    #
    #     eos_tokens = self.eos_tokens
    #
    #     if extra_eos_tokens:
    #         eos_tokens.extend(extra_eos_tokens)
    #     if self.use_open_source_model:
    #         self._update_prompt_template()
    #
    #     outputs = litellm.batch_completion(
    #         model=self.litellm_model_name,
    #         messages=convs_list,
    #         api_key=self.api_key,
    #         temperature=temperature,
    #         top_p=top_p,
    #         max_tokens=max_n_tokens,
    #         num_retries=self.API_MAX_RETRY,
    #         seed=0,
    #         stop=eos_tokens,
    #     )
    #
    #     responses = [output["choices"][0]["message"].content for output in outputs]
    #
    #     return responses

# class LocalvLLM(LanguageModel):
    
#     def __init__(self, model_name: str):
#         """Initializes the LLMHuggingFace with the specified model name."""
#         super().__init__(model_name)
#         if self.model_name not in MODEL_NAMES:
#             raise ValueError(f"Invalid model name: {model_name}")
#         self.hf_model_name = HF_MODEL_NAMES[Model(model_name)]
#         destroy_model_parallel()
#         self.model = vllm.LLM(model=self.hf_model_name)
#         if self.temperature > 0:
#             self.sampling_params = vllm.SamplingParams(
#                 temperature=self.temperature, top_p=self.top_p, max_tokens=self.max_n_tokens
#             )
#         else:
#             self.sampling_params = vllm.SamplingParams(temperature=0, max_tokens=self.max_n_tokens)

#     def _get_responses(self, prompts_list: list[str], max_new_tokens: int | None = None) -> list[str]:
#         """Generates responses from the model for the given prompts."""
#         full_prompt_list = self._prompt_to_conv(prompts_list)
#         outputs = self.model.generate(full_prompt_list, self.sampling_params)
#         # Get output from each input, but remove initial space
#         outputs_list = [output.outputs[0].text[1:] for output in outputs]
#         return outputs_list

#     def _prompt_to_conv(self, prompts_list):
#         batchsize = len(prompts_list)
#         convs_list = [self._init_conv_template() for _ in range(batchsize)]
#         full_prompts = []
#         for conv, prompt in zip(convs_list, prompts_list):
#             conv.append_message(conv.roles[0], prompt)
#             conv.append_message(conv.roles[1], None)
#             full_prompt = conv.get_prompt()
#             # Need this to avoid extraneous space in generation
#             if "llama-2-7b-chat-hf" in self.model_name:
#                 full_prompt += " "
#             full_prompts.append(full_prompt)
#         return full_prompts

#     def _init_conv_template(self):
#         template = get_conversation_template(self.hf_model_name)
#         if "llama" in self.hf_model_name:
#             # Add the system prompt for Llama as FastChat does not include it
#             template.system_message = """You are a helpful, respectful and honest assistant. Always answer as helpfully as possible, while being safe. Your answers should not include any harmful, unethical, racist, sexist, toxic, dangerous, or illegal content. Please ensure that your responses are socially unbiased and positive in nature.\n\nIf a question does not make any sense, or is not factually coherent, explain why instead of answering something not correct. If you don't know the answer to a question, please don't share false information."""
#         return template
    






