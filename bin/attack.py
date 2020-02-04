import client_config as cfg
import json

class Attack:


    def __init__(self,id,start_time=None,stop_time=None,misuse_types=None,peak_bps=None,peak_pps=None,source_ips=None,protocol="UDP",source_port="1234",total_bytes=1,total_packets=1):
        self.id = id
        self.start_time = start_time
        self.stop_time = stop_time
        self.peak_bps = peak_bps
        self.peak_pps = peak_pps
        self.protocol = protocol 
        self.total_bytes = total_bytes
        self.total_packets = total_packets
        self.source_port = source_port
        self.misuse_types = misuse_types #array
        self.source_ips = source_ips #array
        print("peakBPS:{}".format(self.peak_bps))

    def output(self,format='crits'):
        """
        Formats output for varius targets.  Crits is initially supported

        Paramters:
            format: string (eg crits)

        Returns:
            attack: dictionary 

        """
        post_object = {}
        if format == 'crits':
            post_object["ProviderName"] = cfg.provider
            ingest_data_array = []
            for ip in self.source_ips:
                ingest_data_object = {}
                ingest_data_object["IPaddress"]=ip
                ingest_data_object["attackStartTime"] = self.start_time
                ingest_data_object["attackStopTime"] = self.stop_time
                ingest_data_object["attackTypes"] = self.misuse_types
                ingest_data_object["peakBPS"] = self.peak_bps
                ingest_data_object["peakPPS"] = self.peak_pps
                #These are not used in the original client
                #ingest_data_object["sourcePort"] = self.source_port
                #ingest_data_object["protocol"] = self.protocol
                #ingest_data_object["totalBytesSent"] = self.total_bytes
                #ingest_data_object["totalPacketsSent"] = self.total_packets
                ingest_data_array.append(ingest_data_object) 
            post_object['ingestData']=ingest_data_array
        else:
            print("Error: Output format of {} is not correct".format(forma))

        return json.dumps(post_object,indent=4)
