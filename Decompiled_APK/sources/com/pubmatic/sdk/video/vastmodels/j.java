package com.pubmatic.sdk.video.vastmodels;

import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.common.utility.o;
import com.pubmatic.sdk.video.vastmodels.l;
import java.util.ArrayList;
import java.util.List;
import org.w3c.dom.Node;

/* loaded from: classes2.dex */
public class j implements com.pubmatic.sdk.video.xmlserialiser.b {
    private b a = b.NO_ADS;
    private String b;
    private String c;
    private String d;
    private String e;
    private String f;
    private int g;
    private int h;
    private List<String> i;
    private String j;
    private List<String> k;
    private List<String> l;
    private List<String> m;
    private List<String> n;
    private l o;
    private List<com.pubmatic.sdk.video.vastmodels.b> p;
    private j q;
    private List<com.pubmatic.sdk.video.vastmodels.a> r;

    public enum a {
        IMPRESSIONS,
        ERRORS,
        VIEWABLE_IMPRESSIONS,
        NOT_VIEWABLE_IMPRESSIONS,
        VIEW_UNDETERMINED_IMPRESSIONS,
        CLICKTRACKING,
        PROGRESS_TRACKING_EVENT,
        COMPANIONS,
        CLICK_THROUGH,
        ICON
    }

    public enum b {
        INLINE,
        WRAPPER,
        NO_ADS
    }

    private <T> T a(@NonNull a aVar) {
        for (j wrapper = this; wrapper != null; wrapper = wrapper.getWrapper()) {
            T t = (T) c(wrapper, aVar);
            if (t != null) {
                return t;
            }
        }
        return null;
    }

    private List<? extends com.pubmatic.sdk.video.xmlserialiser.b> b(@NonNull j jVar, @NonNull a aVar) {
        int i = k.a[aVar.ordinal()];
        if (i != 9) {
            if (i != 10) {
                return null;
            }
            return jVar.getCompanions();
        }
        if (jVar.getCreative() != null) {
            return jVar.getCreative().getTrackingEvents(l.b.PROGRESS);
        }
        return null;
    }

    private <T> T c(@NonNull j jVar, @NonNull a aVar) {
        List<c> iconList;
        l creative = jVar.getCreative();
        int i = k.a[aVar.ordinal()];
        if (i != 1) {
            if (i == 2 && creative != null && creative.getVastCreativeType() == l.a.LINEAR && (iconList = ((d) creative).getIconList()) != null && iconList.size() > 0) {
                return (T) iconList.get(0);
            }
        } else if (creative != null) {
            return (T) creative.getClickThroughURL();
        }
        return null;
    }

    @Override // com.pubmatic.sdk.video.xmlserialiser.b
    public void build(@NonNull com.pubmatic.sdk.video.xmlserialiser.a aVar) throws IllegalAccessException, InstantiationException {
        String nodeValue;
        if (aVar.getNodeName() != null) {
            if (aVar.getNodeName().equals("InLine")) {
                this.a = b.INLINE;
            } else if (aVar.getNodeName().equals("Wrapper")) {
                this.a = b.WRAPPER;
            }
        }
        try {
            Node node = aVar.getNode("/VAST/Ad");
            if (node != null && (nodeValue = node.getAttributes().getNamedItem("sequence").getNodeValue()) != null) {
                this.h = Integer.parseInt(nodeValue);
            }
        } catch (Exception unused) {
            POBLog.error("POBVastAd", "Unable to find Vast ad sequence due to invalid value", new Object[0]);
        }
        if (this.h < 1) {
            this.h = -1;
        }
        this.b = aVar.getNodeValue("AdSystem");
        this.c = aVar.getNodeValue("AdTitle");
        this.d = aVar.getNodeValue("AdServingId");
        this.e = aVar.getNodeValue("Description");
        this.f = aVar.getNodeValue("Pricing");
        this.g = o.getIntegerValue(aVar.getNodeValue("Expires"));
        this.i = aVar.getStringList("Error");
        this.j = aVar.getNodeValue("VASTAdTagURI");
        this.k = aVar.getStringList("Impression");
        this.l = aVar.getStringList("ViewableImpression/Viewable");
        this.m = aVar.getStringList("ViewableImpression/NotViewable");
        this.n = aVar.getStringList("ViewableImpression/ViewUndetermined");
        l lVar = (l) aVar.getNodeObject("Creatives/Creative/Linear", d.class);
        this.o = lVar;
        if (lVar == null) {
            this.o = (l) aVar.getNodeObject("Creatives/Creative/NonLinearAds/NonLinear", f.class);
        }
        this.p = aVar.getObjectList("Creatives/Creative/CompanionAds/Companion", com.pubmatic.sdk.video.vastmodels.b.class);
        List<com.pubmatic.sdk.video.vastmodels.a> objectList = aVar.getObjectList("AdVerifications/Verification", com.pubmatic.sdk.video.vastmodels.a.class);
        this.r = objectList;
        if (objectList == null || objectList.isEmpty()) {
            this.r = aVar.getObjectList("Extensions/Extension/AdVerifications/Verification", com.pubmatic.sdk.video.vastmodels.a.class);
        }
    }

    public int getAdSequence() {
        return this.h;
    }

    public String getAdServingId() {
        return this.d;
    }

    public String getAdSystem() {
        return this.b;
    }

    public String getAdTitle() {
        return this.c;
    }

    public b getAdType() {
        return this.a;
    }

    public List<com.pubmatic.sdk.video.vastmodels.a> getAdVerification() {
        return this.r;
    }

    public String getClosestClickThroughURL() {
        return (String) a(a.CLICK_THROUGH);
    }

    public c getClosestIcon() {
        return (c) a(a.ICON);
    }

    public List<com.pubmatic.sdk.video.vastmodels.b> getCombinedCompanions() {
        List<com.pubmatic.sdk.video.vastmodels.b> companions = getCompanions();
        if (companions == null) {
            return null;
        }
        ArrayList arrayList = new ArrayList(companions);
        for (j wrapper = getWrapper(); wrapper != null; wrapper = wrapper.getWrapper()) {
            List<com.pubmatic.sdk.video.vastmodels.b> companions2 = wrapper.getCompanions();
            if (companions2 != null) {
                arrayList.addAll(0, companions2);
            }
        }
        return arrayList;
    }

    @NonNull
    public List<String> getCombinedList(@NonNull a aVar) {
        ArrayList arrayList = new ArrayList(a(this, aVar));
        for (j wrapper = getWrapper(); wrapper != null; wrapper = wrapper.getWrapper()) {
            arrayList.addAll(0, a(wrapper, aVar));
        }
        return arrayList;
    }

    public List<com.pubmatic.sdk.video.xmlserialiser.b> getCombinedObjectList(@NonNull a aVar) {
        ArrayList arrayList = new ArrayList();
        List<? extends com.pubmatic.sdk.video.xmlserialiser.b> listB = b(this, aVar);
        if (listB != null) {
            arrayList.addAll(listB);
        }
        for (j wrapper = getWrapper(); wrapper != null; wrapper = wrapper.getWrapper()) {
            List<? extends com.pubmatic.sdk.video.xmlserialiser.b> listB2 = b(wrapper, aVar);
            if (listB2 != null) {
                arrayList.addAll(0, listB2);
            }
        }
        return arrayList;
    }

    @NonNull
    public List<String> getCombinedTrackingEventList(@NonNull l.b bVar) {
        ArrayList arrayList = new ArrayList();
        if (getCreative() != null) {
            arrayList.addAll(getCreative().getTrackingEventUrls(bVar));
        }
        for (j wrapper = getWrapper(); wrapper != null; wrapper = wrapper.getWrapper()) {
            l creative = wrapper.getCreative();
            if (creative != null) {
                arrayList.addAll(creative.getTrackingEventUrls(bVar));
            }
        }
        return arrayList;
    }

    public List<com.pubmatic.sdk.common.viewability.j> getCombinedVerificationList() {
        ArrayList arrayList = new ArrayList();
        List<com.pubmatic.sdk.video.vastmodels.a> adVerification = getAdVerification();
        if (adVerification != null) {
            arrayList.addAll(adVerification);
        }
        for (j wrapper = getWrapper(); wrapper != null; wrapper = wrapper.getWrapper()) {
            List<com.pubmatic.sdk.video.vastmodels.a> adVerification2 = wrapper.getAdVerification();
            if (adVerification2 != null) {
                arrayList.addAll(0, adVerification2);
            }
        }
        return arrayList;
    }

    public List<com.pubmatic.sdk.video.vastmodels.b> getCompanions() {
        return this.p;
    }

    public l getCreative() {
        return this.o;
    }

    public String getDescription() {
        return this.e;
    }

    public List<String> getErrorURLs() {
        return this.i;
    }

    public int getExpires() {
        return this.g;
    }

    public List<String> getImpressions() {
        return this.k;
    }

    public List<String> getNotViewableImpressions() {
        return this.m;
    }

    public String getPricing() {
        return this.f;
    }

    public String getVASTAdTagURI() {
        return this.j;
    }

    public List<String> getViewUndeterminedImpressions() {
        return this.n;
    }

    public List<String> getViewableImpressions() {
        return this.l;
    }

    public j getWrapper() {
        return this.q;
    }

    public void setWrapper(j jVar) {
        this.q = jVar;
    }

    private List<String> a(@NonNull j jVar, @NonNull a aVar) {
        switch (k.a[aVar.ordinal()]) {
            case 3:
                return jVar.getImpressions();
            case 4:
                return jVar.getErrorURLs();
            case 5:
                return jVar.getViewableImpressions();
            case 6:
                return jVar.getNotViewableImpressions();
            case 7:
                return jVar.getViewUndeterminedImpressions();
            case 8:
                ArrayList arrayList = new ArrayList();
                l creative = jVar.getCreative();
                if (creative != null && creative.getClickTrackers() != null) {
                    arrayList.addAll(creative.getClickTrackers());
                }
                return arrayList;
            default:
                return null;
        }
    }
}
