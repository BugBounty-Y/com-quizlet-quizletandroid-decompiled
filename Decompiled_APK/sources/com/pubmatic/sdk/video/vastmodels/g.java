package com.pubmatic.sdk.video.vastmodels;

import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public class g implements com.pubmatic.sdk.video.xmlserialiser.b {
    private a a;
    private String b;
    private String c;

    public enum a {
        STATIC,
        HTML,
        IFRAME
    }

    @Override // com.pubmatic.sdk.video.xmlserialiser.b
    public void build(@NonNull com.pubmatic.sdk.video.xmlserialiser.a aVar) {
        this.b = aVar.getAttributeValue("creativeType");
        if (aVar.getNodeName() != null) {
            String nodeName = aVar.getNodeName();
            nodeName.getClass();
            switch (nodeName) {
                case "IFrameResource":
                    this.a = a.IFRAME;
                    break;
                case "StaticResource":
                    this.a = a.STATIC;
                    break;
                case "HTMLResource":
                    this.a = a.HTML;
                    break;
            }
        }
        this.c = aVar.getNodeValue();
    }

    public String getCreativeType() {
        return this.b;
    }

    public String getResource() {
        return this.c;
    }

    public a getResourceType() {
        return this.a;
    }
}
