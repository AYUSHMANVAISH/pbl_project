import pandas as pd
import glob

def merge_cicids(folder_path):
    all_files = glob.glob(folder_path + "/*.csv")

    df_list = []
    for file in all_files:
        print("Loading:", file)
        df = pd.read_csv(file)
        df_list.append(df)

    merged_df = pd.concat(df_list, ignore_index=True)
    return merged_df

if __name__ == "__main__":
    merged = merge_cicids("data/cicids")
    print("Merged shape:", merged.shape)
    merged.to_csv("data/CICIDS2017_ALL.csv", index=False)
    print("Saved as data/CICIDS2017_ALL.csv")
