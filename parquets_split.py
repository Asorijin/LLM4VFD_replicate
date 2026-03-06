import chromadb
from prompts import SYSTEM_PROMPT_CAVFD, SYSTEM_PROMPT_CCI, SYSTEM_PROMPT_DA, USER_PROMPT_CAVFD, USER_PROMPT_CCI, USER_PROMPT_DA
import os
import pandas as pd
import time
import torch
import torch.nn.functional as F
from tqdm import tqdm
from torch import Tensor
from transformers import AutoTokenizer, AutoModel, AutoModelForCausalLM, BitsAndBytesConfig

import requests


def search_nvd_vulnerabilities(keyword, limit=10):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": limit
    }

    try:
        response = requests.get(url, params=params)
        response.raise_for_status()
        return response.json()['vulnerabilities'][0]['cve']['descriptions'][0]['value']
    except requests.exceptions.RequestException as e:
        print(f"Error accessing NVD API: {e}")
        return None
def proc_test(row):
    print(row['vuln_id'])

#print(search_nvd_vulnerabilities('CVE-2025-8522'))
df = pd.read_parquet('without_embedding_leak_new.parquet')
pd.set_option('display.max_columns',None)
pd.set_option('display.max_rows', None)
df.apply(proc_test, axis=1)
