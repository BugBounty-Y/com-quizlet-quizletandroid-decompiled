package com.pubmatic.sdk.common.models;

import java.net.URL;

/* loaded from: classes2.dex */
public class d {
    private String a;
    private URL b;
    private Boolean c;
    private String d;
    private String e;

    public String getCategories() {
        return this.d;
    }

    public String getDomain() {
        return this.a;
    }

    public String getKeywords() {
        return this.e;
    }

    public URL getStoreURL() {
        return this.b;
    }

    public Boolean isPaid() {
        return this.c;
    }

    public void setCategories(String str) {
        this.d = str;
    }

    public void setDomain(String str) {
        this.a = str;
    }

    public void setKeywords(String str) {
        this.e = str;
    }

    public void setPaid(boolean z) {
        this.c = Boolean.valueOf(z);
    }

    public void setStoreURL(URL url) {
        this.b = url;
    }
}
