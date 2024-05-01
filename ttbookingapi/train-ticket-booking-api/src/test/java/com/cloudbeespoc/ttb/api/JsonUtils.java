package com.cloudbeespoc.ttb.api;

public class JsonUtils {

    public static String json(String singleQuoteJson){
        return (singleQuoteJson).replace("'", "\"");
    }
}
