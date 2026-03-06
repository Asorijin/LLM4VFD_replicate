import time

import chromadb
from prompts import SYSTEM_PROMPT_CAVFD, SYSTEM_PROMPT_CCI, SYSTEM_PROMPT_DA, USER_PROMPT_CAVFD, USER_PROMPT_CCI, USER_PROMPT_DA
import os
import pandas as pd
import torch
import torch.nn.functional as F
from tqdm import tqdm
from torch import Tensor
from transformers import AutoTokenizer, AutoModel, AutoModelForCausalLM, BitsAndBytesConfig
from utils import process_patch
import dashscope
from dashscope import Generation,Messages
from openai import OpenAI
dashscope.api_key='needed'

NVD_API_KEY='needed'

# os.environ['HTTP_PROXY'] = 'http://127.0.0.1:8888'
# os.environ['HTTPS_PROXY'] = 'http://127.0.0.1:8888'

# os.environ["HF_ENDPOINT"] = "https://hf-mirror.com"
# os.environ["HF_HUB_DOWNLOAD_TIMEOUT"] = "600"
# os.environ["HF_HUB_NUM_RETRIES"] = "10"

# we use qwen embedding model in our paper since its open-source, however it require local gpu to run it, you can use openai embedding api to do the embedding and its much faster.
# tokenizer = AutoTokenizer.from_pretrained(
#     "Alibaba-NLP/gte-Qwen2-7B-instruct", trust_remote_code=True,
#     local_files_only=True,
# )
# model = AutoModelForCausalLM.from_pretrained(
#     "Alibaba-NLP/gte-Qwen2-7B-instruct",
#     local_files_only=True,
#     trust_remote_code=True,
#     attn_implementation="eager",
#     torch_dtype=torch.float16,
#     device_map="cuda",
#     cache_dir="D:\\huggingface_cache",
# )
# model = model.to("cuda")
#
# def last_token_pool(last_hidden_states: Tensor, attention_mask: Tensor) -> Tensor:
#     left_padding = attention_mask[:, -1].sum() == attention_mask.shape[0]
#     if left_padding:
#         return last_hidden_states[:, -1]
#     else:
#         sequence_lengths = attention_mask.sum(dim=1) - 1
#         batch_size = last_hidden_states.shape[0]
#         return last_hidden_states[
#             torch.arange(batch_size, device=last_hidden_states.device), sequence_lengths
#         ]
#
# def embed(texts):
#     batch_dict = tokenizer(texts, padding=True, truncation=True, return_tensors="pt").to("cuda")
#     batch_dict["use_cache"]=False
#     outputs = model(**batch_dict)
#     embeddings = last_token_pool(
#         outputs.last_hidden_state, batch_dict["attention_mask"]
#     )
#     embeddings = F.normalize(embeddings, p=2, dim=1)
#     return embeddings.detach().cpu().float().numpy().tolist()
#
#
# def get_embeddings_qwen(texts, batch_size=1):
#     embedding_results = []
#     for i in tqdm(range(0, len(texts), batch_size)):
#         batch_texts = texts[i : i + batch_size]
#         # Process the text to replace newlines with spaces and create batched requests
#         # API call with batched input
#         batch_texts = [text.replace("\n", " ") for text in batch_texts]
#         embeddings = embed(batch_texts)
#         for embedding in embeddings:
#             embedding_results.append(embedding)
#     return embedding_results

import requests


def search_nvd_vulnerabilities(keyword, limit=10):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": limit
    }
    headers={
        "apiKey": NVD_API_KEY,
    }
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        print(response.json())
        time.sleep(1)
        return response.json()['vulnerabilities'][0]['cve']['descriptions'][0]['value']
    except requests.exceptions.RequestException as e:
        print(f"Error accessing NVD API: {e}")
        return None


def add_vf_to_collection(df, collection):
    collection.add(
        documents=df["three_aspect_response"].tolist(),
        embeddings=df["3aspect_embedding"].tolist(),
        metadatas=df[["vuln_id", "commit_id", "repo", "lang", "process_patch"]].to_dict(
            orient="records"
        ),
        ids=df["commit_id"].tolist(),
    )
    return collection

def inference_llm(system_prompt, user_prompt, cache_dir=None):
    if cache_dir:
        if os.path.exists(cache_dir):
            print(f"Cache found at {cache_dir}")
            with open(cache_dir, "r") as f:
                return f.read()
    #client = OpenAI(api_key="needed") # set local host port for vllm host model
    try:
        client = OpenAI(
            # 若没有配置环境变量，请用阿里云百炼API Key将下行替换为：api_key="sk-xxx",
            api_key='needed',
            base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
        )
        response = client.chat.completions.create(
            model='qwen-turbo-1101',
            messages=[
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': user_prompt}
            ]
        )
        content = response.choices[0].message.content
        print(content)

        return content
    except Exception as ex:
        print(ex)
        return None

def generate_cci(patch):
    user_prompt = USER_PROMPT_CCI.substitute(patch_content = patch)
    system_prompt = SYSTEM_PROMPT_CCI
    cci = inference_llm(system_prompt, user_prompt)
    return cci

# def generate_da(title_body):
#     user_prompt = USER_PROMPT_DA.substitute(title_body = title_body)
#     system_prompt = SYSTEM_PROMPT_DA
#     da = inference_llm(system_prompt, user_prompt)
#     return da
#
# def generate_cavfd(patch, cci, da):
#     print(cci)
#     user_prompt = USER_PROMPT_CAVFD.substitute(patch_content = patch, three_aspect_content = cci, IRPR_content = da,
#                                                history_three_aspect_content = "",
#                                                history_vuln_content = ""
#                                                 )
#     system_prompt = SYSTEM_PROMPT_CAVFD
#     cavfd = inference_llm(system_prompt, user_prompt)
#     return cavfd

now_num=0
def process(row):

    global now_num

    patch = row['patch']
    processed_patch = process_patch(patch)
    cci = generate_cci(processed_patch)
    # da = generate_da(row['irpr_title_body'])
    # lang = row['lang']
    lang = None
    # history_cci, history_cve_description = retrieve_from_rag(cci,lang)
    # cavfd = generate_cavfd(patch, cci, da)
    # print(cavfd)
    now_num += 1

    print(now_num)
    return cci

def cve_process(row):
    cve_info = search_nvd_vulnerabilities(row['vuln_id'])
    return cve_info

dataset_dir="without_embedding_leak.parquet"

df = pd.read_parquet(dataset_dir)

df['three_aspect_response_cci'] = df.apply(process, axis=1)
df['cve_info']=df.apply(cve_process, axis=1)
# df['lang'] = df.apply(lang_process, axis=1)

df.to_parquet('without_embedding_leak_new.parquet')

#将三方面意见作为向量嵌入
# df["3aspect_embedding"] = get_embeddings_qwen(
#     df["three_aspect_response"].tolist()
# )
#
# df.to_parquet('with_embedding_leak.parquet')
#
# chroma_client = chromadb.HttpClient(host="localhost", port=8000)
# collection = chroma_client.create_collection(
#     name=f"three_aspect_summary_collection_gte-Qwen2-7B-instruct"
# )
#
# add_vf_to_collection(df, collection)
#
# df.to_parquet('fin_leak.parquet')
#
# print("***********************")
# now_df = pd.read_parquet('fin_leak.parquet')
# pd.set_option('display.max_columns')
# print(now_df)
