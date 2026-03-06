import json
import time

import chromadb

import pandas as pd
import torch.nn.functional as F
from tqdm import tqdm

import dashscope
import utils
from http import HTTPStatus


num = 0
err = 0

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
        global err
        err += 1
        return []


def get_embeddings_qwen(texts, batch_size=1):
    global num
    print(num)
    num+=1
    time.sleep(1)
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

def add_vf_to_collection(df, collection):
    total_rows=len(df)
    batch_size = 5000
    for start_idx in range(0, total_rows, batch_size):
        end_idx = min(start_idx + batch_size, total_rows)
        batch_df = df.iloc[start_idx:end_idx]

        metadata_columns = ["vuln_id", "commit_id", "repo_url", "lang", "processed_patch","cve_info"]
        metadatas = batch_df[metadata_columns].fillna("null").to_dict(orient="records")

        collection.add(
            documents=batch_df["three_aspect_response_cci"].tolist(),
            embeddings=batch_df["3aspect_embedding"].tolist(),
            metadatas=metadatas,
            ids=batch_df["commit_id"].tolist(),
        )
    # metadata_df = df[["vuln_id", "commit_id", "repo_url", "lang", "processed_patch"]].copy()
    # metadata_df = metadata_df.fillna("null")
    # collection.add(
    #     documents=df["three_aspect_response_cci"].tolist(),
    #     embeddings=df["3aspect_embedding"].tolist(),
    #     metadatas=metadata_df[["vuln_id", "commit_id", "repo_url", "lang", "processed_patch"]].to_dict(
    #         orient="records"
    #     ),
    #     ids=df["commit_id"].tolist(),
    # )
    return collection

# df = pd.read_parquet('without_embedding_leak_new.parquet');
#
# df["3aspect_embedding"] = get_embeddings_qwen(
#     df["three_aspect_response_cci"].tolist()
# )
# print("************************")
# print(err)
# df.to_parquet('with_embedding_leak.parquet')

def proc(row):
    patch = row['patch']
    processed_patch = utils.process_patch(patch)
    return  processed_patch

df = pd.read_parquet('with_embedding_leak.parquet')

pd.set_option('display.max_columns',None)
print(df)
# exit()
chroma_client = chromadb.PersistentClient(path='./chroma_db')
collection = chroma_client.create_collection(
    name=f"three_aspect_summary_collection_gte-Qwen2-7B-instruct"
)

add_vf_to_collection(df, collection)


print("***********************")