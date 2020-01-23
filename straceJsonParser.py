import re
import json
    
class StraceOutput:
    regular_expressions=[r"^([_\w\d]+)\(([\w\d\s\"\=\[\]\,\/\.\-\|\}\{\*\<\>\`\\]*)\)\s+=\s+(-?[\d]*)\s([\w]*\s?)\(?([\w\s]*)\)?$",
                         r"^([_\w\d]+)\(([\w\d\s\"\=\[\]\,\/\.\-\|\}\{\*\<\>\`\\]*)\)\s+=\s+(-?[\d]*)$",
                        r"^([_\w\d]+)\(([\w\d\s\"\=\[\]\,\/\.\-\|\}\{\*\<\>\`\\]*)\)\s+=\s+(0x[\da-f]*)$",
                        r"^([\d]{2}:{1}[\d]{2}:{1}[\d]{2})\s([_\w\d]+)\(([\w\d\s\"\=\[\]\,\/\.\-\|\}\{\*\<\>\`\\]*)\)\s+=\s+(-?[\d]*)$",
                        r"^([\d]{2}:{1}[\d]{2}:{1}[\d]{2})\s([_\w\d]+)\(([\w\d\s\"\=\[\]\,\/\.\-\|\}\{\*\<\>\`\\]*)\)\s+=\s+(-?[\d]*)\s([\w]*\s?)\(?([\w\s]*)\)?$",
                        r"^([\d]{2}:{1}[\d]{2}:{1}[\d]{2})\s([_\w\d]+)\(([\w\d\s\"\=\[\]\,\/\.\-\|\}\{\*\<\>\`\\]*)\)\s+=\s+(0x[\da-f]*)$",
                        r"^([\d]{2}:{1}[\d]{2}:{1}[\d]{2})\s\[([\da-f]*)\]\s([_\w\d]+)\(([\w\d\s\"\=\[\]\,\/\.\-\|\}\{\*\<\>\`\\]*)\)\s+=\s+(0x[\da-f]*)$",
                        r"^([\d]{2}:{1}[\d]{2}:{1}[\d]{2}\.[\d]{6})\s([_\w\d]+)\(([\w\d\s\"\=\[\]\,\/\.\-\|\}\{\*\<\>\`\\]*)\)\s+=\s+(-?[\d]*)\s([\w]*\s?)\(?([\w\s]*)\)?$",
                        r"^([\d]{2}:{1}[\d]{2}:{1}[\d]{2}\.[\d]{6})\s([_\w\d]+)\(([\w\d\s\"\=\[\]\,\/\.\-\|\}\{\*\<\>\`\\]*)\)\s+=\s+(-?[\d]*)$",
                        r"^([\d]{2}:{1}[\d]{2}:{1}[\d]{2})\s\[([\da-f]*)\]\s([_\w\d]+)\(([\w\d\s\"\=\[\]\,\/\.\-\|\}\{\*\<\>\`\\]*)\)\s+=\s+(-?[\d]*)\s([\w]*\s?)\(?([\w\s]*)\)?$",
                        r"^([\d]{2}:{1}[\d]{2}:{1}[\d]{2})\s\[([\da-f]*)\]\s([_\w\d]+)\(([\w\d\s\"\=\[\]\,\/\.\-\|\}\{\*\<\>\`\\]*)\)\s+=\s+(-?[\d]*)$",
                        r"^([\d]{4})\s*\[([\da-f]*)\]\s([_\w\d]+)\(([\w\d\s\"\=\[\]\,\/\.\-\|\}\{\*\<\>\`\\]*)\)\s+=\s+(-?[\d]*)$",
                        r"^([\d]{4})\s*\[([\da-f]*)\]\s([_\w\d]+)\(([\w\d\s\"\=\[\]\,\/\.\-\|\}\{\*\<\>\`\\]*)\)\s+=\s+(-?[\d]*)\s([\w]*\s?)\(?([\w\s]*)\)?$",
                        r"^([\d]{4})\s*\[([\da-f]*)\]\s([_\w\d]+)\(([\w\d\s\"\=\[\]\,\/\.\-\|\}\{\*\<\>\`\\]*)\)\s+=\s+(0x[\da-f]*)$"

                        ]
    def __init__(self,sys_call,argument,return_value,process_id=None,any_explain=None,return_macro=None,exec_time=0,sys_clk_time=0,ip=None,reg_match=None):
        self.sys_call=sys_call
        self.argument=argument
        self.return_value=return_value
        self.any_explain=any_explain
        self.exec_time=exec_time
        self.return_macro=return_macro
        self.sys_clk_time=sys_clk_time
        self.ip=ip
        self.process_id=process_id
        self.reg_match=reg_match
        
    
    @classmethod
    def createStrace(cls,data):
        straceObj=None
        if re.match(cls.regular_expressions[0],data):
            match=re.match(cls.regular_expressions[0],data).groups()
            straceObj=cls(sys_call=match[0],argument=match[1],return_value=match[2],return_macro=match[3],any_explain=match[4],reg_match=cls.regular_expressions[0])
        elif re.match(cls.regular_expressions[1],data):
            match=re.match(cls.regular_expressions[1],data).groups()
            straceObj=cls(sys_call=match[0],argument=match[1],return_value=match[2],reg_match=cls.regular_expressions[1])
        elif re.match(cls.regular_expressions[2],data):
            match=re.match(cls.regular_expressions[2],data).groups()
            straceObj=cls(sys_call=match[0],argument=match[1],return_value=match[2],reg_match=cls.regular_expressions[2])
        elif re.match(cls.regular_expressions[3],data):
            match=re.match(cls.regular_expressions[3],data)(match).groups()
            straceObj=cls(sys_clk_time=match[0],sys_call=match[1],argument=match[2],return_value=match[3],reg_match=cls.regular_expressions[3])
        elif re.match(cls.regular_expressions[4],data):
            match=re.match(cls.regular_expressions[4],data).groups()
            straceObj=cls(sys_clk_time=match[0],sys_call=match[1],argument=match[2],return_value=match[3],return_macro=match[4],any_explain=match[5],reg_match=cls.regular_expressions[4])
        elif re.match(cls.regular_expressions[5],data):
            match=re.match(cls.regular_expressions[5],data).groups()
            straceObj=cls(sys_clk_time=[0],sys_call=match[1],argument=match[2],return_value=match[3],reg_match=cls.regular_expressions[5])    
        elif re.match(cls.regular_expressions[6],data):
            match=re.match(cls.regular_expressions[6],data).groups()
            straceObj=cls(sys_clk_time=[0],ip=match[1],sys_call=match[2],argument=match[3],return_value=match[4],reg_match=cls.regular_expressions[6])    
        elif re.match(cls.regular_expressions[7],data):
            match=re.match(cls.regular_expressions[7],data).groups()
            straceObj=cls(sys_clk_time=match[0],sys_call=match[1],argument=match[2],return_value=match[3],return_macro=match[4],any_explain=match[5],reg_match=cls.regular_expressions[7])
        elif re.match(cls.regular_expressions[8],data):
            match=re.match(cls.regular_expressions[8],data).groups()
            straceObj=cls(sys_clk_time=match[0],sys_call=match[1],argument=match[2],return_value=match[3],reg_match=cls.regular_expressions[8])
        elif re.match(cls.regular_expressions[9],data):
            match=re.match(cls.regular_expressions[9],data).groups()
            straceObj=cls(sys_clk_time=match[0],ip=match[1],sys_call=match[2],argument=match[3],return_value=match[4],reg_match=cls.regular_expressions[9])    
        elif re.match(cls.regular_expressions[10],data):
            match=re.match(cls.regular_expressions[10],data).groups()
            straceObj=cls(sys_clk_time=match[0],ip=match[1],sys_call=match[2],argument=match[3],return_value=match[4],reg_match=cls.regular_expressions[10])
        elif re.match(cls.regular_expressions[11],data):
            match=re.match(cls.regular_expressions[11],data).groups()
            straceObj=cls(process_id=match[0],sys_call=match[2],ip=match[1],argument=match[3],return_value=match[4],reg_match=cls.regular_expressions[11])
        elif re.match(cls.regular_expressions[12],data):
            match=re.match(cls.regular_expressions[12],data).groups()
            straceObj=cls(process_id=match[0],sys_call=match[2],ip=match[1],argument=match[3],return_value=match[4],return_macro=match[5],any_explain=match[6],reg_match=cls.regular_expressions[12])
        elif re.match(cls.regular_expressions[13],data):
            match=re.match(cls.regular_expressions[13],data).groups()
            straceObj=cls(process_id=match[0],sys_call=match[2],ip=match[1],argument=match[3],return_value=match[4],reg_match=cls.regular_expressions[13])


        return straceObj
            
    @classmethod
    def fromFile(cls,path):
        path=open(path,'r')
        listOfData=[]
        lines=path.read().split("\n")
        print("Total System Calls Executed Length: {}".format(len(lines)))
        for line in lines:
            obj=StraceOutput.createStrace(line)
            if obj is not None:
                listOfData.append(obj)
        print("Total Line Parsed: {}".format(len(listOfData)))
        return listOfData
    
    def __str__(self):
        if self.reg_match==StraceOutput.regular_expressions[0]:
            return "{}({}) = {} {} ({})".format(self.sys_call,self.argument,self.return_value,self.return_macro,self.any_explain)
        elif self.reg_match==StraceOutput.regular_expressions[1]:
            return "{}({}) = {}".format(self.sys_call,self.argument,self.return_value)
        elif self.reg_match==StraceOutput.regular_expressions[2]:
            return "{}({}) = {}".format(self.sys_call,self.argument,self.return_value)
        elif self.reg_match==StraceOutput.regular_expressions[3]:
            return "{} {}({}) = {}".format(self.sys_clk_time,self.sys_call,self.argument,self.return_value)
        elif self.reg_match==StraceOutput.regular_expressions[4]:
            return "{} {}({}) = {} {} ({})".format(self.sys_clk_time,self.sys_call,self.argument,self.return_value,self.return_macro,self.any_explain)
        elif self.reg_match==StraceOutput.regular_expressions[5]:
            return "{} {}({}) = {}".format(self.sys_clk_time,self.sys_call,self.argument,self.return_value)
        elif self.reg_match==StraceOutput.regular_expressions[6]:
            return "{} {} {}({}) = {}".format(self.sys_clk_time,self.ip,self.sys_call,self.argument,self.return_value)
        elif self.reg_match==StraceOutput.regular_expressions[7]:
            return "{} {}({}) = {} {} ({})".format(self.sys_clk_time,self.sys_call,self.argument,self.return_value,self.return_macro,self.any_explain)
        elif self.reg_match==StraceOutput.regular_expressions[8]:
            return "{} {}({}) = {}".format(self.sys_clk_time,self.sys_call,self.argument,self.return_value)
        elif self.reg_match==StraceOutput.regular_expressions[9]:
            return "{} [{}] {}({}) = {}".format(self.sys_clk_time,self.ip,self.sys_call,self.argument,self.return_value)
        elif self.reg_match==StraceOutput.regular_expressions[10]:
            return "{} [{}] {}({}) = {}".format(self.sys_clk_time,self.ip,self.sys_call,self.argument,self.return_value)
        elif self.reg_match==StraceOutput.regular_expressions[11]:
            return "{} [{}] {}({}) = {}".format(self.process_id,self.ip,self.sys_call,self.argument,self.return_value)
        elif self.reg_match==StraceOutput.regular_expressions[12]:
            return "{} [{}] {}({}) = {} {} ({})".format(self.process_id,self.ip,self.sys_call,self.argument,self.return_value)
        elif self.reg_match==StraceOutput.regular_expressions[13]:
            return "{} [{}] {}({}) = {} {}".format(self.process_id,self.ip,self.sys_call,self.argument,self.return_value)

        
    def __repr__(self):
        if self.reg_match==StraceOutput.regular_expressions[0]:
            return "{}({}) = {} {} ({})".format(self.sys_call,self.argument,self.return_value,self.return_macro,self.any_explain)
        elif self.reg_match==StraceOutput.regular_expressions[1]:
            return "{}({}) = {}".format(self.sys_call,self.argument,self.return_value)
        elif self.reg_match==StraceOutput.regular_expressions[2]:
            return "{}({}) = {}".format(self.sys_call,self.argument,self.return_value)
        elif self.reg_match==StraceOutput.regular_expressions[3]:
            return "{} {}({}) = {}".format(self.sys_clk_time,self.sys_call,self.argument,self.return_value)
        elif self.reg_match==StraceOutput.regular_expressions[4]:
            return "{} {}({}) = {} {} ({})".format(self.sys_clk_time,self.sys_call,self.argument,self.return_value,self.return_macro,self.any_explain)
        elif self.reg_match==StraceOutput.regular_expressions[5]:
            return "{} {}({}) = {}".format(self.sys_clk_time,self.sys_call,self.argument,self.return_value)
        elif self.reg_match==StraceOutput.regular_expressions[6]:
            return "{} {} {}({}) = {}".format(self.sys_clk_time,self.ip,self.sys_call,self.argument,self.return_value)
        elif self.reg_match==StraceOutput.regular_expressions[7]:
            return "{} {}({}) = {} {} ({})".format(self.sys_clk_time,self.sys_call,self.argument,self.return_value,self.return_macro,self.any_explain)
        elif self.reg_match==StraceOutput.regular_expressions[8]:
            return "{} {}({}) = {}".format(self.sys_clk_time,self.sys_call,self.argument,self.return_value)
        elif self.reg_match==StraceOutput.regular_expressions[9]:
            return "{} {} {}({}) = {}".format(self.sys_clk_time,self.ip,self.sys_call,self.argument,self.return_value)
        elif self.reg_match==StraceOutput.regular_expressions[10]:
            return "{} {} {}({}) = {}".format(self.sys_clk_time,self.ip,self.sys_call,self.argument,self.return_value)
        elif self.reg_match==StraceOutput.regular_expressions[11]:
            return "{} [{}] {}({}) = {}".format(self.process_id,self.ip,self.sys_call,self.argument,self.return_value)
        elif self.reg_match==StraceOutput.regular_expressions[12]:
            return "{} [{}] {}({}) = {} {} ({})".format(self.process_id,self.ip,self.sys_call,self.argument,self.return_value)
        elif self.reg_match==StraceOutput.regular_expressions[13]:
            return "{} [{}] {}({}) = {} {}".format(self.process_id,self.ip,self.sys_call,self.argument,self.return_value)

    @classmethod
    def saveJson(cls,data,filename="data.json"):
        with open(filename,'w') as f:
            json.dump([item.__dict__ for item in data],f)
