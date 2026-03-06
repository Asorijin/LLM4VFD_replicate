from prompts import SYSTEM_PROMPT_CAVFD, SYSTEM_PROMPT_CCI, SYSTEM_PROMPT_DA, USER_PROMPT_CAVFD, USER_PROMPT_CCI, \
    USER_PROMPT_DA
import chromadb
import json
import os
import pandas as pd
import requests
from openai import OpenAI
from tqdm.auto import tqdm
import torch
import torch.nn.functional as F
from tqdm import tqdm
from torch import Tensor
from transformers import AutoTokenizer, AutoModel
from utils import process_patch
import dashscope
from http import HTTPStatus
# all models use openai api

def inference_llm(system_prompt, user_prompt, cache_dir=None):
    if cache_dir:
        if os.path.exists(cache_dir):
            print(f"Cache found at {cache_dir}")
            with open(cache_dir, "r") as f:
                return f.read()
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
    user_prompt = USER_PROMPT_CCI.substitute(patch_content=patch)
    system_prompt = SYSTEM_PROMPT_CCI
    cci = inference_llm(system_prompt, user_prompt)
    return cci


def generate_da(title_body):
    user_prompt = USER_PROMPT_DA.substitute(title_body=title_body)
    system_prompt = SYSTEM_PROMPT_DA
    da = inference_llm(system_prompt, user_prompt)
    return da


def generate_cavfd(patch, cci, da, history_cci, history_cve_description):
    user_prompt = USER_PROMPT_CAVFD.substitute(patch_content=patch, three_aspect_content=cci, IRPR_content=da
                                               , history_three_aspect_content=history_cci,
                                               history_vuln_content=history_cve_description
                                               )
    system_prompt = SYSTEM_PROMPT_CAVFD
    cavfd = inference_llm(system_prompt, user_prompt)
    return cavfd



dashscope.api_key='needed'

def embed(texts):
    inputs = texts
    resp = dashscope.TextEmbedding.call(
        model="text-embedding-v4",
        input=inputs
    )
    if resp['status_code'] == HTTPStatus.OK:
        embeddings = resp["output"]["embeddings"][0]["embedding"]
        return embeddings
    else:
        print("err!")
        print(resp)
        return []


def get_embeddings_qwen(texts, batch_size=1):
    embedding_results = []
    for i in tqdm(range(0, len(texts), batch_size)):
        batch_texts = texts[i : i + batch_size]
        # Process the text to replace newlines with spaces and create batched requests
        # API call with batched input
        if batch_texts is None:
            batch_texts = ["None"]

        batch_texts = [(text or "").replace("\n", " ") for text in batch_texts]
        embeddings = embed(batch_texts)
        embedding_results.append(embeddings)

    return embedding_results


def query_collection_lang(collection_name, query_embeddings, lang="Java"):
    client = chromadb.PersistentClient(path='./chroma_db')

    collection = client.get_collection(collection_name)
    result = collection.query(
        query_embeddings=query_embeddings, n_results=1, where={"lang": lang}
    )
    return result





def retrieve_from_rag(cci, lang="Java"):
    collection_name = 'three_aspect_summary_collection_gte-Qwen2-7B-instruct'
    cci_embedding = get_embeddings_qwen([cci])
    cci_embedding = cci_embedding[0]
    exp_result = query_collection_lang(collection_name, cci_embedding, lang)
    retrieved_3aspect = exp_result["documents"][0][0]
    retrieved_cve_id = exp_result["metadatas"][0][0]["vuln_id"]
    retrieved_cve_description = exp_result["metadatas"][0][0]["cve_info"]
    return retrieved_3aspect, retrieved_cve_description

dataset_dir = 'my_test.parquet'


def process(row):
    patch = row['patch']
    processed_patch = process_patch(patch)
    cci = generate_cci(processed_patch)
    da = generate_da(row['title_body'])
    # lang = row['lang']
    history_cci, history_cve_description = retrieve_from_rag(cci)
    cavfd = generate_cavfd(patch, cci, da, history_cci, history_cve_description)
    print(cavfd)
    return cavfd


df = pd.read_parquet(dataset_dir)
df['patch'] = df['patch'].fillna('').astype(str)
df['cavfd'] = df.apply(process, axis=1)

df.to_csv('fin.csv')