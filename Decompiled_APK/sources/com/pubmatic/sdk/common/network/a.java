package com.pubmatic.sdk.common.network;

import androidx.annotation.NonNull;
import java.util.HashMap;
import java.util.Map;

/* loaded from: classes2.dex */
public class a implements Cloneable {
    private String d;
    private String e;
    private String f;
    private int a = 5000;
    private int b = 0;
    private float c = 1.0f;
    private EnumC0011a h = EnumC0011a.GET;

    @NonNull
    private Map<String, String> g = new HashMap();

    /* renamed from: com.pubmatic.sdk.common.network.a$a, reason: collision with other inner class name */
    public enum EnumC0011a {
        GET,
        POST,
        PUT,
        DELETE
    }

    @NonNull
    public Map<String, String> getHeaders() {
        return this.g;
    }

    public String getPostData() {
        return this.f;
    }

    public EnumC0011a getRequestMethod() {
        return this.h;
    }

    public String getRequestTag() {
        return this.d;
    }

    public float getRetryBackoffMultiplier() {
        return this.c;
    }

    public int getRetryCount() {
        return this.b;
    }

    public int getTimeout() {
        return this.a;
    }

    public String getUrl() {
        return this.e;
    }

    public void setHeaders(@NonNull Map<String, String> map) {
        this.g = map;
    }

    public void setPostData(String str) {
        this.f = str;
    }

    public void setRequestMethod(EnumC0011a enumC0011a) {
        this.h = enumC0011a;
    }

    public void setRequestTag(String str) {
        this.d = str;
    }

    public void setRetryBackoffMultiplier(float f) {
        this.c = f;
    }

    public void setRetryCount(int i) {
        this.b = i;
    }

    public void setTimeout(int i) {
        this.a = i;
    }

    public void setUrl(String str) {
        this.e = str;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getUrl());
        if (getRequestMethod() == EnumC0011a.POST) {
            sb.append("\nPOST Data : ");
            sb.append(getPostData());
        } else {
            sb.append(getPostData());
        }
        return sb.toString();
    }

    /* renamed from: clone, reason: merged with bridge method [inline-methods] */
    public a m24clone() throws CloneNotSupportedException {
        return (a) super.clone();
    }
}
