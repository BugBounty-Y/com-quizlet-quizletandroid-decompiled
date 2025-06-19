package com.pubmatic.sdk.video.vastmodels;

import androidx.annotation.NonNull;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public class i implements com.pubmatic.sdk.video.xmlserialiser.b {
    private List<j> a;
    private String b;

    @Override // com.pubmatic.sdk.video.xmlserialiser.b
    public void build(@NonNull com.pubmatic.sdk.video.xmlserialiser.a aVar) throws IllegalAccessException, InstantiationException {
        this.b = aVar.getAttributeValue("version");
        this.a = new ArrayList();
        if (aVar.getNode("/VAST/Ad") == null) {
            j jVar = new j();
            jVar.build(aVar);
            this.a.add(jVar);
            return;
        }
        j jVar2 = (j) aVar.getNodeObject("/VAST/Ad[1]/InLine", j.class);
        if (jVar2 != null) {
            this.a.add(jVar2);
            return;
        }
        j jVar3 = (j) aVar.getNodeObject("/VAST/Ad[1]/Wrapper", j.class);
        if (jVar3 != null) {
            this.a.add(jVar3);
        }
    }

    public List<j> getAds() {
        return this.a;
    }

    public String getVersion() {
        return this.b;
    }
}
