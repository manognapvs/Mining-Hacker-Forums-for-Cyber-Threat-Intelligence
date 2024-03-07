from pyintelowl import IntelOwl
import pandas as pd

IOC_dict = {
    'urls':[],
    'ipv4s': [],
    'domains': []
}

def remove_empty_values(row, ioc_name):
    for i in row:
        if i != '':
            for k in range(len(i)):
                i[k] = i[k].replace("'", "")
                i[k] = i[k].replace(" ", "")
            IOC_dict[ioc_name].extend(i)
    return

def count_iocs(row):
  count = []
  for i in row.to_list():
    i = i.replace("[", "")
    i = i.replace("]", "")
    if i != '':
      i = i.split(",")
    count.append(i)
  return count

def preprocess_input(ranking:list):
    ioc_extracted_data = pd.read_csv("../dataset/output-10000-ioc_extractor.csv")

    # URLs
    iocs_grouped_by_authors = pd.DataFrame({'urls' : ioc_extracted_data.groupby('txtAuthor')['urls'].apply(count_iocs)}).reset_index()

    hacker_and_iocs = iocs_grouped_by_authors[iocs_grouped_by_authors['txtAuthor'].isin(ranking)]

    hacker_and_iocs['urls'].apply((lambda x: remove_empty_values(x, 'urls')))


    # IPv4
    iocs_grouped_by_authors = pd.DataFrame({'ipv4s' : ioc_extracted_data.groupby('txtAuthor')['ipv4s'].apply(count_iocs)}).reset_index()

    hacker_and_iocs = iocs_grouped_by_authors[iocs_grouped_by_authors['txtAuthor'].isin(ranking)]

    hacker_and_iocs['ipv4s'].apply((lambda x: remove_empty_values(x, 'ipv4s')))


    # DOMAINs
    iocs_grouped_by_authors = pd.DataFrame({'domains' : ioc_extracted_data.groupby('txtAuthor')['domains'].apply(count_iocs)}).reset_index()

    hacker_and_iocs = iocs_grouped_by_authors[iocs_grouped_by_authors['txtAuthor'].isin(ranking)]

    hacker_and_iocs['domains'].apply((lambda x: remove_empty_values(x, 'domains')))

    return


def call_intelOwl():
    intelOwl_obj = IntelOwl(
        "6d3666df3cbf612272539d61e14d34da",
        "http://localhost:80",
    )
    for url in IOC_dict['urls'][:100]:
        intelOwl_obj.send_observable_analysis_request(observable_name=url, analyzers_requested=['URLhaus', 'UrlScan_Search', 'CryptoScamDB_CheckAPI', 'MalwareBazaar_Google_Observable'], connectors_requested=["OpenCTI"], tlp="WHITE", observable_classification="url")
    
    for ipv4 in IOC_dict['ipv4s']:
        intelOwl_obj.send_observable_analysis_request(observable_name=ipv4, analyzers_requested=['URLhaus', 'UrlScan_Search','AbuseIPDB', 'CryptoScamDB_CheckAPI', 'GreyNoiseCommunity', 'FireHol_IPList', 'MalwareBazaar_Google_Observable'], connectors_requested=["OpenCTI"], tlp="WHITE", observable_classification="ip")
    
    for domain in IOC_dict['domains']:
        intelOwl_obj.send_observable_analysis_request(observable_name=domain, analyzers_requested=['URLhaus', 'UrlScan_Search','Classic_DNS', 'MalwareBazaar_Google_Observable'], connectors_requested=["OpenCTI"], tlp="WHITE", observable_classification="domain")


def main():

    ranking = ["dvsocks", "mata00", "rai10", "viruslover", "dichvusocks"]

    preprocess_input(ranking)

    call_intelOwl()

if __name__ == '__main__':
    main()