import gc
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

def proc(row):
    print(row['three_aspect_response_cci'])

df = pd.read_parquet('without_embedding_leak_new.parquet')
pd.set_option('display.max_rows',None)

print(df['three_aspect_response_cci'].head(15000))