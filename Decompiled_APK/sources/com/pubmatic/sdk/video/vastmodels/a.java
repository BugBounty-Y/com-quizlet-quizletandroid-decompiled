package com.pubmatic.sdk.video.vastmodels;

import androidx.annotation.NonNull;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import java.util.List;

/* loaded from: classes2.dex */
public class a implements com.pubmatic.sdk.video.xmlserialiser.b, com.pubmatic.sdk.common.viewability.j {
    private List<String> a;
    private List<String> b;
    private List<h> c;
    private String d;
    private String e;

    @Override // com.pubmatic.sdk.video.xmlserialiser.b
    public void build(@NonNull com.pubmatic.sdk.video.xmlserialiser.a aVar) {
        this.d = aVar.getAttributeValue(OTUXParamsKeys.OT_UX_VENDOR);
        this.a = aVar.getStringList("JavaScriptResource");
        this.c = aVar.getObjectList("TrackingEvents/Tracking", h.class);
        this.b = aVar.getStringList("ExecutableResource");
        this.e = aVar.getNodeValue("VerificationParameters");
    }

    public List<String> getExecutableResource() {
        return this.b;
    }

    @Override // com.pubmatic.sdk.common.viewability.j
    public List<String> getJavaScriptResource() {
        return this.a;
    }

    public List<h> getTrackingEvents() {
        return this.c;
    }

    @Override // com.pubmatic.sdk.common.viewability.j
    public String getVendorKey() {
        return this.d;
    }

    @Override // com.pubmatic.sdk.common.viewability.j
    public String getVerificationParameter() {
        return this.e;
    }
}
