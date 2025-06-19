package com.pubmatic.sdk.video.vastmodels;

import androidx.annotation.NonNull;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.pubmatic.sdk.common.utility.o;
import com.pubmatic.sdk.video.vastmodels.l;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public class f extends l {
    private int a;
    private int b;
    private int c;
    private int d;
    private String e;
    private boolean f;
    private boolean g = true;
    private List<h> h;
    private String i;
    private List<String> j;
    private List<g> k;
    private String l;

    @Override // com.pubmatic.sdk.video.vastmodels.l, com.pubmatic.sdk.video.xmlserialiser.b
    public void build(@NonNull com.pubmatic.sdk.video.xmlserialiser.a aVar) {
        this.a = o.getIntegerValue(aVar.getAttributeValue(OTUXParamsKeys.OT_UX_WIDTH));
        this.b = o.getIntegerValue(aVar.getAttributeValue(OTUXParamsKeys.OT_UX_HEIGHT));
        this.c = o.getIntegerValue(aVar.getAttributeValue("expandedWidth"));
        this.d = o.getIntegerValue(aVar.getAttributeValue("expandedHeight"));
        this.e = aVar.getAttributeValue("minSuggestedDuration");
        this.f = o.getBooleanValue(aVar.getAttributeValue("scalable"));
        String attributeValue = aVar.getAttributeValue("maintainAspectRatio");
        if (attributeValue != null && !attributeValue.isEmpty()) {
            this.g = o.getBooleanValue(attributeValue);
        }
        this.h = aVar.getObjectList("TrackingEvents/Tracking", h.class);
        this.i = aVar.getNodeValue("NonLinearClickThrough");
        this.j = aVar.getStringList("NonLinearClickTracking");
        this.k = new ArrayList();
        g gVar = (g) aVar.getNodeObject("StaticResource", g.class);
        if (gVar != null) {
            this.k.add(gVar);
        }
        g gVar2 = (g) aVar.getNodeObject("HTMLResource", g.class);
        if (gVar2 != null) {
            this.k.add(gVar2);
        }
        g gVar3 = (g) aVar.getNodeObject("IFrameResource", g.class);
        if (gVar3 != null) {
            this.k.add(gVar3);
        }
        this.l = aVar.getNodeValue("../../UniversalAdId");
    }

    @Override // com.pubmatic.sdk.video.vastmodels.l
    public String getClickThroughURL() {
        return this.i;
    }

    @Override // com.pubmatic.sdk.video.vastmodels.l
    public List<String> getClickTrackers() {
        return this.j;
    }

    public int getExpandedHeight() {
        return this.d;
    }

    public int getExpandedWidth() {
        return this.c;
    }

    public int getHeight() {
        return this.b;
    }

    public boolean getMaintainAspectRatio() {
        return this.g;
    }

    public String getMinSuggestedDuration() {
        return this.e;
    }

    public List<g> getResource() {
        return this.k;
    }

    public boolean getScalable() {
        return this.f;
    }

    @Override // com.pubmatic.sdk.video.vastmodels.l
    public List<h> getTrackingEvents() {
        return this.h;
    }

    public String getUniversalAdId() {
        return this.l;
    }

    @Override // com.pubmatic.sdk.video.vastmodels.l
    public l.a getVastCreativeType() {
        return l.a.NONLINEAR;
    }

    public int getWidth() {
        return this.a;
    }
}
