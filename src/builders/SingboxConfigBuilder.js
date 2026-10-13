import { SING_BOX_CONFIG, generateRuleSets, generateRules, DIRECT_DEFAULT_RULES, REJECT_ACTION_RULES } from '../config/index.js';
import { BaseConfigBuilder } from './BaseConfigBuilder.js';
import { deepCopy, groupProxiesByCountry } from '../utils.js';
import { addProxyWithDedup } from './helpers/proxyHelpers.js';
import { buildSelectorMembers as buildSelectorMemberList, buildNodeSelectMembers, buildCustomRuleMembers, uniqueNames } from './helpers/groupBuilder.js';
import { normalizeGroupName } from './helpers/groupNameUtils.js';


export class SingboxConfigBuilder extends BaseConfigBuilder {

constructor(
inputString,
selectedRules,
customRules,
baseConfig,
lang,
userAgent,
groupByCountry = false,
enableClashUI = false,
externalController,
externalUiDownloadUrl,
singboxVersion = '1.14',
includeAutoSelect = true
){

super(
inputString,
baseConfig ?? SING_BOX_CONFIG,
lang,
userAgent,
groupByCountry,
includeAutoSelect
);


this.selectedRules = selectedRules;
this.customRules = customRules;

this.countryGroupNames = [];
this.manualGroupName = null;

this.enableClashUI = enableClashUI;
this.externalController = externalController;
this.externalUiDownloadUrl = externalUiDownloadUrl;
this.singboxVersion = singboxVersion;


// 禁止 provider 模式
delete this.config.outbound_providers;


if(Array.isArray(this.config.outbounds)){
    this.config.outbounds.forEach(outbound=>{
        if(outbound){
            delete outbound.providers;
        }
    });
}


this.normalizeDnsRules();


if(
this.config?.dns?.servers?.length > 0
){
    this.config.dns.servers[0].detour =
    this.t('outboundNames.Node Select');
}

}


/**
 * 不允许机场配置覆盖自己的 sing-box 模板
 */
applyConfigOverrides(overrides){

if(
!overrides ||
typeof overrides !== 'object' ||
Array.isArray(overrides)
){
return;
}


const safeOverrides={
...overrides
};


const blockedKeys=[

'dns',
'route',
'outbounds',
'outbound_providers',
'providers',
'tun',

'ntp',
'experimental',
'endpoints',
'services',

'proxy-groups',
'rules',
'rule-providers',


'port',
'socks-port',
'mixed-port',
'redir-port',
'tproxy-port',

'allow-lan',
'bind-address',

'mode',
'log-level',

'external-controller',
'external-ui',
'external-ui-url',

'secret'

];


blockedKeys.forEach(key=>{
delete safeOverrides[key];
});


super.applyConfigOverrides(
safeOverrides
);

}



/**
 * 节点最终清洗
 * sing-box 1.14 strict mode
 */
sanitizeOutbound(outbound){

if(
!outbound ||
typeof outbound !== 'object'
){
return outbound;
}


const removeFields=[

'udp',

'skip-cert-verify',

'network',

'ws-opts',
'ws_opts',

'ports',

'plugin',
'plugin-opts',

'packet_encoding',

'providers'

];


removeFields.forEach(
field=>{
delete outbound[field];
}
);


return outbound;

}



convertProxy(proxy){

const sanitized={
...proxy
};


// Clash字段删除
delete sanitized.udp;



// port 转 server_port

if(
sanitized.server_port === undefined &&
sanitized.port !== undefined
){

sanitized.server_port =
sanitized.port;

}

delete sanitized.port;



// VLESS flow

if(
sanitized.type === 'vless'
){

const flow =
typeof sanitized.flow === 'string'
?
sanitized.flow.trim()
:
'';


if(flow === 'xtls-rprx-vision'){

sanitized.flow=flow;

}else{

delete sanitized.flow;

}

}
// hysteria2

if(
sanitized.type === 'hysteria2'
){

// Clash up/down 转 sing-box 格式

if(sanitized.up !== undefined){

sanitized.up_mbps =
Number(
String(sanitized.up)
.replace(/[^0-9.]/g,'')
);

delete sanitized.up;

}


if(sanitized.down !== undefined){

sanitized.down_mbps =
Number(
String(sanitized.down)
.replace(/[^0-9.]/g,'')
);

delete sanitized.down;

}


// sing-box 1.14 不支持 Clash ports
// 直接删除，不转换

delete sanitized.ports;
delete sanitized.server_ports;

}



// websocket


if(
sanitized.network === 'ws'
){

const wsOpts =
sanitized['ws-opts'] ||
sanitized.ws_opts ||
{};


sanitized.transport={

...(sanitized.transport || {}),

type:'ws'

};



if(wsOpts.path){

sanitized.transport.path =
wsOpts.path;

}


if(
wsOpts.headers &&
typeof wsOpts.headers === 'object'
){

sanitized.transport.headers =
wsOpts.headers;

}



delete sanitized.network;

delete sanitized['ws-opts'];

delete sanitized.ws_opts;

}




// alpn

if(
sanitized.alpn &&
sanitized.tls
){

if(!sanitized.tls.alpn){

sanitized.tls={
...sanitized.tls,
alpn:sanitized.alpn
};

}


delete sanitized.alpn;


}else if(
sanitized.alpn
){

delete sanitized.alpn;

}




// Clash遗留字段

delete sanitized.packet_encoding;

delete sanitized.providers;


// 最后一层清洗

return this.sanitizeOutbound(
sanitized
);

}




addProxyToConfig(proxy){

this.config.outbounds =
this.config.outbounds || [];


// 写入前再次过滤

const cleaned =
this.sanitizeOutbound(
deepCopy(proxy)
);



addProxyWithDedup(

this.config.outbounds,

cleaned,

{

getName:item=>item?.tag,


setName:(item,name)=>{

if(item){

item.tag=name;

}

},



isSame:(existing={},incoming={})=>{


const {
tag:_a,
...restA
}=existing;


const {
tag:_b,
...restB
}=incoming;


return JSON.stringify(restA)
===
JSON.stringify(restB);


}

}

);


}





hasOutboundTag(tag){


const target =
normalizeGroupName(tag);


return (
this.config.outbounds || []
)
.some(
outbound=>
normalizeGroupName(
outbound?.tag
)
=== target
);


}




hasAutoSelectCandidates(
proxyList=this.getProxyList()
){

return (
Array.isArray(proxyList)
&&
proxyList.length>0
);

}




addSelectors(){


this.config.outbounds =
(
this.config.outbounds || []
)
.filter(
outbound=>
outbound.type!=='selector'
&&
outbound.type!=='urltest'
);



const proxyList =
this.getProxyList();



this.addAutoSelectGroup(
proxyList
);


this.addNodeSelectGroup(
proxyList
);



this.pendingUserProxyGroups=[];


}




addAutoSelectGroup(proxyList){


if(!this.includeAutoSelect)
return;



const tag =
this.t('outboundNames.Auto Select');



const members =
uniqueNames(proxyList);



if(!members.length)
return;



this.config.outbounds.unshift({

type:'urltest',

tag,

interval:'30m',

outbounds:members

});


}




addNodeSelectGroup(proxyList){


const tag =
this.t('outboundNames.Node Select');



const members =
buildNodeSelectMembers({

proxyList,

translator:this.t,

groupByCountry:
this.groupByCountry,

manualGroupName:
this.manualGroupName,

countryGroupNames:
this.countryGroupNames,

includeAutoSelect:
this.includeAutoSelect &&
this.hasAutoSelectCandidates(proxyList),

includeReject:false

});



this.config.outbounds.unshift({

type:'selector',

tag,

outbounds:members

});


}
validateOutbounds(){


const proxyList =
this.getProxyList();


const invalidTags =
new Set();



(
this.config.outbounds || []

)
.forEach(outbound=>{


if(
!outbound ||
(
outbound.type!=='selector'
&&
outbound.type!=='urltest'
)

){

return;

}



delete outbound.providers;



if(
!Array.isArray(outbound.outbounds)
||
outbound.outbounds.length===0
){


if(proxyList.length){

outbound.outbounds =
[
...proxyList
];


}else{


invalidTags.add(
normalizeGroupName(
outbound.tag
)
);


}


}


});



if(invalidTags.size){


this.config.outbounds =
(
this.config.outbounds || []
)

.filter(
outbound=>
!invalidTags.has(
normalizeGroupName(
outbound?.tag
)
)

)

.map(outbound=>{


if(
Array.isArray(outbound.outbounds)
){

outbound.outbounds =
outbound.outbounds.filter(
tag=>
!invalidTags.has(
normalizeGroupName(tag)
)
);

}


return outbound;


});


}


}






sanitizeLegacySpecialOutbounds(){


const removeTags =
new Set();



(
this.config.outbounds || []

)
.forEach(outbound=>{


if(
outbound?.type==='dns'
||
outbound?.type==='block'
){

removeTags.add(
normalizeGroupName(
outbound.tag
)
);

}


});



removeTags.add(
normalizeGroupName('REJECT')
);



this.config.outbounds =
(
this.config.outbounds || []
)

.filter(
outbound=>
!removeTags.has(
normalizeGroupName(
outbound?.tag
)
)

)

.map(outbound=>{


delete outbound.providers;


if(
Array.isArray(outbound.outbounds)
){

outbound.outbounds =
outbound.outbounds.filter(
tag=>
!removeTags.has(
normalizeGroupName(tag)
)
);

}


return outbound;


});



}






formatConfig(){



// 最终输出前清洗

this.config.outbounds =
(
this.config.outbounds || []
)

.map(outbound=>{


return this.sanitizeOutbound(
outbound
);


});




// 删除空 selector/urltest

this.config.outbounds =
this.config.outbounds.filter(
outbound=>{


if(
outbound.type==='selector'
||
outbound.type==='urltest'
){

return (
Array.isArray(outbound.outbounds)
&&
outbound.outbounds.length>0
);

}


return true;


});



// DNS 最终规范

this.normalizeDnsRules();


// 清理 legacy

this.sanitizeLegacySpecialOutbounds();


// 检查代理组

this.validateOutbounds();



return this.config;

}



}