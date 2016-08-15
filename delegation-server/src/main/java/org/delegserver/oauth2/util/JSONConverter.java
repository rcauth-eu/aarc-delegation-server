package org.delegserver.oauth2.util;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;

public class JSONConverter {

	private static JSONParser parser = new JSONParser(0);
	
	public static JSONObject toJSONObject(Map<String,?> map) {
		return new JSONObject(map);
	}
	
	public static Map<String, ?> fromJSONObject(String json) {
		Map map = null;
		try {
    		
    		Object obj = parser.parse(json);
			
    		if ( obj instanceof JSONObject ) {
    			map = (Map) obj;
    		}
		
		} catch (ParseException e) {
			throw new GeneralException("Error while parsing JSONObject! Could not parse JSON: " + json , e);
		}
		
		return map;		
	}
	
	public static Map<String,String> fromJSONObjectToStringMap(String json) {
		Map map = (Map<String, String>) fromJSONArray(json);
		return map;
	}
	
	
	public static JSONArray toJSONArray(List<String> list) {
		JSONArray json = new JSONArray();
		for (String s : list) {
			json.add(s);
		}		
		return json;
	}
	
	public static JSONArray toJSONArray(String[] list) {
		return toJSONArray(Arrays.asList(list));
	}	
	
	public static List<String> fromJSONArray(String json) {
		try {
			Object parsedObj = parser.parse(json);
			if (parsedObj instanceof JSONArray) {
				return (List<String>) parsedObj;
			}
		} catch (ParseException e) {
			throw new GeneralException("Error while parsing JSONArray! Could not parse JSON: " + json, e);
		}
		return null;
	}	
}
