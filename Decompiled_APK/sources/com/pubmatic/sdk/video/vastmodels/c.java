package com.pubmatic.sdk.video.vastmodels;

import androidx.annotation.NonNull;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.pubmatic.sdk.common.utility.o;
import com.pubmatic.sdk.video.vastmodels.g;
import java.util.List;
import java.util.Map;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class c implements com.pubmatic.sdk.video.xmlserialiser.b, com.pubmatic.sdk.common.base.c {
    private String a;
    private int b;
    private int c;
    private String d;
    private String e;
    private int f;
    private int g;
    private String h;
    private g i;
    protected String mClickThroughURL;
    protected List<String> mClickTrackers;
    protected List<String> mViewTrackers;

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
        return AbstractC0147y.e("<a href = \"", o.isNullOrEmpty(this.mClickThroughURL) ? "https://obplaceholder.click.com/" : this.mClickThroughURL, "\">", android.support.v4.media.session.a.B("<img src = \"", this.i.getResource(), "\" style = \"display: block; width:100%; height: 100%;\"/>"), "</a>");
    }

    @Override // com.pubmatic.sdk.video.xmlserialiser.b
    public void build(@NonNull com.pubmatic.sdk.video.xmlserialiser.a aVar) {
        this.a = aVar.getAttributeValue("program");
        this.b = o.getIntegerValue(aVar.getAttributeValue(OTUXParamsKeys.OT_UX_WIDTH));
        this.c = o.getIntegerValue(aVar.getAttributeValue(OTUXParamsKeys.OT_UX_HEIGHT));
        this.d = aVar.getAttributeValue("xPosition");
        this.e = aVar.getAttributeValue("yPosition");
        String attributeValue = aVar.getAttributeValue("duration");
        if (attributeValue != null) {
            this.f = (int) o.getSeconds(attributeValue);
        }
        String attributeValue2 = aVar.getAttributeValue("offset");
        if (attributeValue2 != null) {
            this.g = (int) o.getSeconds(attributeValue2);
        }
        this.h = aVar.getAttributeValue("apiFramework");
        this.mClickThroughURL = aVar.getNodeValue("IconClicks/IconClickThrough");
        this.mClickTrackers = aVar.getStringList("IconClicks/IconClickTracking");
        this.mViewTrackers = aVar.getStringList("IconViewTracking");
        g gVar = (g) aVar.getNodeObject("StaticResource", g.class);
        this.i = gVar;
        if (gVar == null) {
            g gVar2 = (g) aVar.getNodeObject("HTMLResource", g.class);
            this.i = gVar2;
            if (gVar2 == null) {
                this.i = (g) aVar.getNodeObject("IFrameResource", g.class);
            }
        }
    }

    @Override // com.pubmatic.sdk.common.base.c
    public com.pubmatic.sdk.common.base.c buildWithRefreshAndExpiryTimeout(int i, int i2) {
        return null;
    }

    public String getApiFramework() {
        return this.h;
    }

    @Override // com.pubmatic.sdk.common.base.c
    public String getBundle() {
        return null;
    }

    public String getClickThroughURL() {
        return this.mClickThroughURL;
    }

    public List<String> getClickTrackers() {
        return this.mClickTrackers;
    }

    @Override // com.pubmatic.sdk.common.base.c
    public int getContentHeight() {
        return this.c;
    }

    @Override // com.pubmatic.sdk.common.base.c
    public int getContentWidth() {
        return this.b;
    }

    @Override // com.pubmatic.sdk.common.base.c
    public String getCreativeType() {
        return null;
    }

    @Override // com.pubmatic.sdk.common.base.c
    public int getDspId() {
        return 0;
    }

    public int getDuration() {
        return this.f;
    }

    @Override // com.pubmatic.sdk.common.base.c
    public String getId() {
        return null;
    }

    public int getOffset() {
        return this.g;
    }

    public String getProgram() {
        return this.a;
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

    public List<String> getViewTrackers() {
        return this.mViewTrackers;
    }

    public String getXPosition() {
        return this.d;
    }

    public String getYPosition() {
        return this.e;
    }

    @Override // com.pubmatic.sdk.common.base.c
    public boolean isCompanion() {
        return false;
    }

    @Override // com.pubmatic.sdk.common.base.c
    public boolean isVideo() {
        return false;
    }
}
