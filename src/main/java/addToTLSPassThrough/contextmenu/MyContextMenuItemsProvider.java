/*
 * Copyright (c) 2023. PortSwigger Ltd. All rights reserved.
 *
 * This code may be used to extend the functionality of Burp Suite Community Edition
 * and Burp Suite Professional, provided that this usage does not violate the
 * license terms for those products.
 */

package addToTLSPassThrough.contextmenu;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class MyContextMenuItemsProvider implements ContextMenuItemsProvider
{

    private final MontoyaApi api;

    public MyContextMenuItemsProvider(MontoyaApi api)
    {

        this.api = api;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event)
    {
        if (event.isFromTool(ToolType.PROXY, ToolType.TARGET, ToolType.LOGGER))
        {
            List<Component> menuItemList = new ArrayList<>();
            JSONArray rulesArray = new JSONArray(); //an array of JSON objects representing single rules

            List<HttpRequestResponse> requestResponses = new ArrayList<>();
            //If the context menu was opened within the Request/Response viewer
            if(event.messageEditorRequestResponse().isPresent()){
                requestResponses.add(event.messageEditorRequestResponse().get().requestResponse());
            //else if it was opened from the list in Proxy/Logger
            } else {
                requestResponses = event.selectedRequestResponses();
            }
            
            
            for(HttpRequestResponse requestResponse : requestResponses) {
                //Extract host values        
                burp.api.montoya.http.HttpService requestService = requestResponse.httpService();
                
                
                String host = requestService.host();

                
                //find number of subdomains
                long domainCount = host.chars().filter(ch -> ch == '.').count();
                //1 = domain.com
                //2 = one.subdomain.com
                //3 = two.s.ubdomains.com
                //4 = thr.e.e.subdomains.com
                
                //String domainCountS = "" + domainCount;
                //api.logging().logToOutput(domainCountS);
                
                //For each level of subdomain, add a new rule to the rulesArray, which is then used to populate the context menu with options
                for(int i=(int) domainCount; i >= 1 ; i--) {

                    org.json.JSONObject newHostJson = new JSONObject();
                    newHostJson.put("port","^" + Integer.toString(requestService.port()) + "$");
                    newHostJson.put("protocol","https");
                    newHostJson.put("file","^.*$");
                    newHostJson.put("enabled", Boolean.parseBoolean("true"));
                    
                    
                    if (i == (int) domainCount){
                        //this matches Burp's default paste-into-settings behavior in regard to host regex format
                        //I.E., No wildcard for base hostname
                        newHostJson.put("host",("^" + host.replace(".", "\\.") + "$"));
                    } else {
                        //Add wildcard to all other subdomain levels
                        newHostJson.put("host",("^.*\\." + host.replace(".", "\\.")       + "$"));
                    }

                    rulesArray.put(newHostJson);

                    
                    //We are iterating over the "host" string, stripping off one subdomain level each loop
                    host = host.substring(host.indexOf(".")).substring(1);  
                }

                //api.logging().logToOutput("rules array after domainCount loop: "+ rulesArray.toString());

            }
            //create JMenuItems
            
            
            JMenuItem all = new JMenuItem("ALL");
            all.addActionListener(new ActionListener(){
                public void actionPerformed(ActionEvent e){
                    //api.logging().logToOutput("In ALL execution. Rules array:" + rulesArray.toString());
                    for(int i=0; i < rulesArray.length(); i++){
                        //iterate through and add all regexes (subdomain level rules)
                        addSingleToTlsPassthrough(rulesArray.getJSONObject(i));
                        
                    }

                }
            });

            menuItemList.add(all);


            for(int i=0;i< rulesArray.length();i++){

                org.json.JSONObject currentItem = rulesArray.getJSONObject(i);
                
                //api.logging().logToOutput("in single menuItemList add (not ALL)");
                
                JMenuItem newItem = new JMenuItem(currentItem.get("host").toString()); //adjust regex backslashes for display
                newItem.addActionListener(new ActionListener(){
                    public void actionPerformed(ActionEvent e){

                        addSingleToTlsPassthrough(currentItem); 
                    }
                });

                menuItemList.add(newItem);

            }
            
            return menuItemList;
        }

        return null; //not Proxy, Logger, or Target so return null
    }
    
        
    public void addSingleToTlsPassthrough(org.json.JSONObject newTlsPassthrough){
        //get current TLS passthrough settings
        String fullPrefix = "{\"proxy\":{\"ssl_pass_through\":{\"rules\":";
        //String rulePrefix = "{\"enabled\":true,\"host\":\"";
        //String ruleSuffix = "\",\"protocol\":\"any\"}";
        String fullSuffix = "}}}";


        //Import current TLSPassthrough rules into new JSONArray. Burp always gives us the prefix/suffix JSON as envelope, so we need to parse down to the rules themselves each time.
        org.json.JSONObject burpRules = new org.json.JSONObject(api.burpSuite().exportProjectOptionsAsJson("proxy.ssl_pass_through.rules"));
        org.json.JSONArray rulesArray = burpRules.getJSONObject("proxy").getJSONObject("ssl_pass_through").getJSONArray("rules");
        
        //Check for duplicate rules.
        //If duplicate, set "file" parameter to wildcard and enable it, overwriting the previous value
        //Presumably, if there is an existing rule, the user shouldn't be able to select it in Burp because it won't reach the Proxy, being TLS Passthrough'd
        //Therefore, that means that the first rule is broken if they are setting a duplicate. It is either not enabled, or the file parameter not being wildcarded is borking it.
        Boolean foundMatchingRule = false;
        for (int i = 0; i < rulesArray.length(); ++i) {
            
            if(foundMatchingRule) { break; }
            
            JSONObject rule = rulesArray.getJSONObject(i);
            //if host and port are already in rules table
            //then something about the rule isn't working. Either it's not enabled
            //or the file parameter is screwing it up.
            
            if (rule.getString("host").equals(newTlsPassthrough.getString("host")) && rule.getString("port").equals(newTlsPassthrough.getString("port"))) {
                foundMatchingRule = true;
                //Clear out file param
                String originalRule = rule.toString();
                rule.put("file", newTlsPassthrough.getString("file")); //always wildcard regex
                //enable it
                rule.put("enabled", true);
                //If it's duplicate, just update the existing rule
                rulesArray.put(i,rule);
                String importString = fullPrefix + rulesArray.toString() + fullSuffix;
                //Write back.
                
                //api.logging().logToOutput("Duplicate rule. Original rule: " + originalRule);
                api.logging().logToOutput("executing importProject with the following: " + importString);
                
                api.burpSuite().importProjectOptionsFromJson(importString);
                break;
            }
        }
        if(foundMatchingRule) {
            
            return;
        }
        //push the new json object into the array
        rulesArray.put(newTlsPassthrough);
        String importString = fullPrefix + rulesArray.toString() + fullSuffix;
        api.logging().logToOutput("No duplicate found. executing importProject with the following: " + importString);
        api.burpSuite().importProjectOptionsFromJson(importString);
    }
}

/* Burp's export format, having used Paste-add: 

{
    "proxy":{
        "ssl_pass_through":{
            "rules":[
                {
                    "enabled":true,
                    "file":"^/log.*",
                    "host":"^play\\.google\\.com$",
                    "port":"^443$",
                    "protocol":"https"
                }
            ]
        }
    }
}
*/