#!/usr/bin/env python3

import prisma_sase
import io
import requests
import json
import csv
import time
import os
import termtables as tt
import yaml
import argparse

global tsg

def sdk_login_to_controller(filepath):
    with open(filepath) as f:
        client_secret_dict = yaml.safe_load(f)
        client_id = client_secret_dict["client_id"]
        client_secret = client_secret_dict["client_secret"]
        tsg_id_str = client_secret_dict["scope"]
        global tsg
        tsg = tsg_id_str.split(":")[1]
        #print(client_id, client_secret, tsg)

    global sdk 
    sdk = prisma_sase.API(controller="https://sase.paloaltonetworks.com/", ssl_verify=False)
   
    sdk.interactive.login_secret(client_id, client_secret, tsg)
    #print("--------------------------------")
    #print("Script Execution Progress: ")
    #print("--------------------------------")
    #print("Login to TSG ID {} successful".format(tsg))



def create_csv_output_file(Header, RList):
    with open('tunnel-status.csv', mode='w') as csv_file:
        csvwriter = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        csvwriter.writerow(Header)
        for Rec in RList:
            csvwriter.writerow(Rec)

def create_json_output_file():
    #create a dictionary
    data_dict = {}
 
    with open('tunnel-status.csv', encoding = 'utf-8') as csv_file_handler:
        csv_reader = csv.DictReader(csv_file_handler)
        i=0
        for rows in csv_reader:
            key = i
            data_dict[key] = rows
            i += 1
 
    with open('tunnel-status.json', 'w', encoding = 'utf-8') as json_file_handler:
        json_file_handler.write(json.dumps(data_dict, indent = 4))

def fetch_endpoint_list(cpuUsage, memoryUsage, days):
    last_n_days_str = "last_"+ str(days)+ "_days"

    url = "https://api.sase.paloaltonetworks.com/adem/telemetry/v2/measure/agent/score?timerange="+last_n_days_str+"&group=en.endpoint,en.user&endpoint-type=muAgent&response-type=grouped-summary&result-filter=Score.endpointScore==poor,fair,good"
    header = {
           "prisma-tenant": tsg
    }
    sdk._session.headers.update(header)

    resp = sdk.rest_call(url=url, method="GET")
    try:
        pass
        #prisma_sase.jd_detailed(resp)
    except:
        print("No data found.")
        exit(0)
  
    #print(resp.json()) 
    resp = resp.json()
    try: 
        collection_list = resp["collection"]
        #print(collection_list)
    except:
        print("No ADEM Data found for users with experience score less than {} for the past {} days".format(exp_score_str, days))
        exit(0)  
    
    user_list = []
    data_list = resp["collection"]
    for data in data_list:
        endpoint_entry = {}
        endpoint_entry["id"] = data["id"]["endpoint"]
        endpoint_entry["user"] = data["id"]["user"]
        user_list.append(endpoint_entry)
    #print(user_list)

    affected_user_list = []

    for endpoint_entry in user_list:
        user = endpoint_entry["user"]
        id = endpoint_entry["id"]
        url = "https://api.sase.paloaltonetworks.com/adem/telemetry/v2/measure/agent/score?timerange="+last_n_days_str+"&filter=username=="+user+"&endpoint-type=muAgent&response-type=timeseries&include=ap.cpuMax,ap.ramMax"
        header = {
           "prisma-tenant": tsg
        }
        sdk._session.headers.update(header)
        #print(resp)
        resp = sdk.rest_call(url=url, method="GET")

        try:
            #prisma_sase.jd_detailed(resp)
            series = resp.json()["series"]
            cpuMaxCnt = 0
            memMaxCnt = 0
            endpointScoreAvg = 0
            cpuUsageAvg = 0
            memoryUsageAvg = 0
            for datapoint in series:
                if datapoint["cpuMax"] >= cpuUsage:
                    cpuMaxCnt += 1
                    if cpuUsageAvg == 0:
                        cpuUsageAvg = datapoint["cpuMax"]
                    else:
                        cpuUsageAvg = (cpuUsageAvg + datapoint["cpuMax"])/2
                    if endpointScoreAvg == 0:
                        endpointScoreAvg = datapoint["endpointScore"]
                    else:
                        endpointScoreAvg = (endpointScoreAvg + datapoint["endpointScore"])/2
                if datapoint["ramMax"] >= memoryUsage:
                    memMaxCnt += 1
                    if memoryUsageAvg == 0:
                        memoryUsageAvg = datapoint["ramMax"]
                    else:
                        memoryUsageAvg = (cpuUsageAvg + datapoint["ramMax"])/2
                    if endpointScoreAvg == 0:
                        endpointScoreAvg = datapoint["endpointScore"]
                    else:
                        endpointScoreAvg = (endpointScoreAvg + datapoint["endpointScore"])/2
            #print(cpuMaxCnt, memMaxCnt) 
            if cpuMaxCnt >= 5 and memMaxCnt >= 5:
                affected_user = {}
                affected_user["Name"] = user
                affected_user["Endpoint ID"]= id
                affected_user["Endpoint Score"] = endpointScoreAvg
                affected_user["CPU Usage"] = cpuUsageAvg
                affected_user["Memory Usage"] = memoryUsageAvg
                affected_user_list.append(affected_user)

        except:
            print("No data found.")
            #exit(0)

    #print(affected_user_list)
    
    Header = ["Users","Endpoint ID", "Endpoint Score", "CPU Usage", "Memory Usage"]
    RList = []
    index = 0
   
    for affected_user in affected_user_list:
        RList.append([affected_user["Name"],affected_user["Endpoint ID"],affected_user["Endpoint Score"],affected_user["CPU Usage"],affected_user["Memory Usage"]])

    if RList != []:
        create_csv_output_file(Header,RList)
        create_json_output_file()

        table_string = tt.to_string(RList, Header, style=tt.styles.ascii_thin_double)
        print(table_string)

def go():
    parser = argparse.ArgumentParser(description='Retrieve all end points (user devices) with CPU , memory greater than given set of values for more than 5 times for a given period of time, endpoint score is used to measure device performance')
    parser.add_argument('-t1', '--T1Secret', help='Input secret file in .yml format for the tenant(T1) ',default="T1-secret.yml")
    parser.add_argument('-cpuUsage', '--cpuUsage', help='CPU usage in percentage ',default='90')  
    parser.add_argument('-memoryUsage', '--memoryUsage', help='Memory usage in percentage ',default='90')  
    parser.add_argument('-days', '--Days', help='Data fetched for the last n days ',default=7)

    args = parser.parse_args()
    T1_secret_filepath = args.T1Secret
    cpuUsage = int(args.cpuUsage)
    memoryUsage = int(args.memoryUsage)
    days = int(args.Days)

    #Pass the secret of 'from tenant' to login
    sdk_login_to_controller(T1_secret_filepath)

    #ADEM APIs to fetch endpoints with CPU , memory greater than a given set of values for more than 5 times for a given period of time.
    fetch_endpoint_list(cpuUsage, memoryUsage, days)

if __name__ == "__main__":
    go()
