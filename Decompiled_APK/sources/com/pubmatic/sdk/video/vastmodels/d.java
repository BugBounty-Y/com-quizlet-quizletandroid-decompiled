package com.pubmatic.sdk.video.vastmodels;

import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.utility.o;
import com.pubmatic.sdk.video.vastmodels.l;
import java.util.List;

/* loaded from: classes2.dex */
public class d extends l {
    private double a;
    private List<h> b;
    private String c;
    private List<e> d;
    private List<c> e;
    private String f;
    private double g = -1.0d;

    @Override // com.pubmatic.sdk.video.vastmodels.l, com.pubmatic.sdk.video.xmlserialiser.b
    public void build(@NonNull com.pubmatic.sdk.video.xmlserialiser.a aVar) throws NumberFormatException {
        this.f = aVar.getNodeValue("../UniversalAdId");
        String nodeValue = aVar.getNodeValue("Duration");
        if (nodeValue != null) {
            this.a = o.getSeconds(nodeValue);
        }
        this.b = aVar.getObjectList("TrackingEvents/Tracking", h.class);
        this.mClickThroughURL = aVar.getNodeValue("VideoClicks/ClickThrough");
        this.mClickTrackers = aVar.getStringList("VideoClicks/ClickTracking");
        this.c = aVar.getNodeValue("VideoClicks/CustomClick");
        this.d = aVar.getObjectList("MediaFiles/MediaFile", e.class);
        this.e = aVar.getObjectList("Icons/Icon", c.class);
        String attributeValue = aVar.getAttributeValue("skipoffset");
        if (attributeValue == null) {
            this.g = -1.0d;
            return;
        }
        double dConvertToSeconds = o.convertToSeconds(nodeValue, attributeValue);
        this.g = dConvertToSeconds;
        this.g = Math.max(0.0d, dConvertToSeconds);
    }

    public String getCustomClick() {
        return this.c;
    }

    public double getDuration() {
        return this.a;
    }

    public List<c> getIconList() {
        return this.e;
    }

    public List<e> getMediaFiles() {
        return this.d;
    }

    public double getSkipOffset() {
        return this.g;
    }

    @Override // com.pubmatic.sdk.video.vastmodels.l
    public List<h> getTrackingEvents() {
        return this.b;
    }

    public String getUniversalAdId() {
        return this.f;
    }

    @Override // com.pubmatic.sdk.video.vastmodels.l
    public l.a getVastCreativeType() {
        return l.a.LINEAR;
    }
}
