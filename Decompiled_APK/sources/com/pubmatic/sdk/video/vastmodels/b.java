package com.pubmatic.sdk.video.vastmodels;

import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.pubmatic.sdk.common.utility.o;
import com.pubmatic.sdk.video.vastmodels.g;
import com.pubmatic.sdk.video.vastmodels.l;
import java.util.List;
import java.util.Map;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class b extends l implements com.pubmatic.sdk.common.base.c {
    private int a;
    private int b;
    private int c;
    private int d;
    private String e;
    private List<h> f;
    private String g;
    private List<String> h;
    private g i;
    private String j;
    private String k;

    private String a() {
        g gVar = this.i;
        if (gVar == null) {
            return null;
        }
        if (gVar.getResourceType() == g.a.HTML) {
            return this.i.getResource();
        }
        if (this.i.getResourceType() != g.a.STATIC) {
            return android.support.v4.media.session.a.B("<iframe src =\"", this.i.getResource(), "\" width = \"100%\" height = \"100%\" frameBorder=\"0\" style = \"display: inline;max-height:100%; max-width: 100%;\" />");
        }
        return AbstractC0147y.e("<a href = \"", o.isNullOrEmpty(this.g) ? "https://obplaceholder.click.com/" : this.g, "\">", android.support.v4.media.session.a.B("<img src = \"", this.i.getResource(), "\" style = \"display: block; width:100%; height: 100%; object-fit:scale-down; background-color:black;\"/>"), "</a>");
    }

    @Override // com.pubmatic.sdk.video.vastmodels.l, com.pubmatic.sdk.video.xmlserialiser.b
    public void build(@NonNull com.pubmatic.sdk.video.xmlserialiser.a aVar) {
        this.a = o.getIntegerValue(aVar.getAttributeValue(OTUXParamsKeys.OT_UX_WIDTH));
        this.b = o.getIntegerValue(aVar.getAttributeValue(OTUXParamsKeys.OT_UX_HEIGHT));
        this.c = o.getIntegerValue(aVar.getAttributeValue("assetWidth"));
        this.d = o.getIntegerValue(aVar.getAttributeValue("assetHeight"));
        this.e = aVar.getAttributeValue("apiFramework");
        this.f = aVar.getObjectList("TrackingEvents/Tracking", h.class);
        this.g = aVar.getNodeValue("CompanionClickThrough");
        this.h = aVar.getStringList("CompanionClickTracking");
        this.k = aVar.getAttributeValue("renderingMode");
        g gVar = (g) aVar.getNodeObject("HTMLResource", g.class);
        this.i = gVar;
        if (gVar == null) {
            g gVar2 = (g) aVar.getNodeObject("StaticResource", g.class);
            this.i = gVar2;
            if (gVar2 == null) {
                this.i = (g) aVar.getNodeObject("IFrameResource", g.class);
            }
        }
        this.j = aVar.getNodeValue("../../UniversalAdId");
    }

    @Override // com.pubmatic.sdk.common.base.c
    public com.pubmatic.sdk.common.base.c buildWithRefreshAndExpiryTimeout(int i, int i2) {
        return null;
    }

    public String getApiFramework() {
        return this.e;
    }

    public int getAssetHeight() {
        return this.d;
    }

    public int getAssetWidth() {
        return this.c;
    }

    @Override // com.pubmatic.sdk.common.base.c
    public String getBundle() {
        return null;
    }

    @Override // com.pubmatic.sdk.video.vastmodels.l
    public String getClickThroughURL() {
        return this.g;
    }

    @Override // com.pubmatic.sdk.video.vastmodels.l
    public List<String> getClickTrackers() {
        return this.h;
    }

    @Override // com.pubmatic.sdk.common.base.c
    public int getContentHeight() {
        return this.b;
    }

    @Override // com.pubmatic.sdk.common.base.c
    public int getContentWidth() {
        return this.a;
    }

    @Override // com.pubmatic.sdk.common.base.c
    public String getCreativeType() {
        return l.a.COMPANION.name();
    }

    @Override // com.pubmatic.sdk.common.base.c
    public int getDspId() {
        return 0;
    }

    public int getHeight() {
        return this.b;
    }

    @Override // com.pubmatic.sdk.common.base.c
    public String getId() {
        return null;
    }

    @Override // com.pubmatic.sdk.common.base.c
    public JSONObject getRawBid() {
        return null;
    }

    @Override // com.pubmatic.sdk.common.base.c
    public int getRefreshInterval() {
        return 0;
    }

    @Override // com.pubmatic.sdk.common.base.c
    public String getRenderableContent() {
        return a();
    }

    public String getRenderingMode() {
        return this.k;
    }

    public g getResource() {
        return this.i;
    }

    @Override // com.pubmatic.sdk.common.base.c
    public int getStatus() {
        return 0;
    }

    @Override // com.pubmatic.sdk.common.base.c
    public Map<String, String> getTargetingInfo() {
        return null;
    }

    @Override // com.pubmatic.sdk.video.vastmodels.l
    public List<h> getTrackingEvents() {
        return this.f;
    }

    public String getUniversalAdId() {
        return this.j;
    }

    @Override // com.pubmatic.sdk.video.vastmodels.l
    public l.a getVastCreativeType() {
        return l.a.COMPANION;
    }

    public int getWidth() {
        return this.a;
    }

    @Override // com.pubmatic.sdk.common.base.c
    public boolean isCompanion() {
        return true;
    }

    @Override // com.pubmatic.sdk.common.base.c
    public boolean isVideo() {
        return false;
    }

    public void setRenderingMode(String str) {
        this.k = str;
    }

    @NonNull
    public String toString() {
        StringBuilder sb = new StringBuilder("POBCompanion{width=");
        sb.append(this.a);
        sb.append(", height=");
        sb.append(this.b);
        sb.append(", renderingMode='");
        return android.support.v4.media.session.a.t(sb, this.k, "'}");
    }
}
