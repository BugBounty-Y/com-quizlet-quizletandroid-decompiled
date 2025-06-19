package com.pubmatic.sdk.video.vastmodels;

import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public class h implements com.pubmatic.sdk.video.xmlserialiser.b {
    private String a;
    private String b;
    private String c;

    @Override // com.pubmatic.sdk.video.xmlserialiser.b
    public void build(@NonNull com.pubmatic.sdk.video.xmlserialiser.a aVar) {
        this.a = aVar.getAttributeValue("event");
        this.b = aVar.getNodeValue();
        this.c = aVar.getAttributeValue("offset");
    }

    public String getEvent() {
        return this.a;
    }

    public String getOffset() {
        return this.c;
    }

    public String getUrl() {
        return this.b;
    }
}
