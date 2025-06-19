package com.pubmatic.sdk.openwrap.core;

import androidx.annotation.NonNull;
import com.j256.ormlite.stmt.query.SimpleComparison;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.openwrap.core.v;
import java.util.List;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class p {
    private Map<String, List<String>> a;

    @NonNull
    protected v.b adPosition;

    @NonNull
    protected final String adUnitId;
    private c b;
    private y c;
    private s d;
    private boolean e;
    private boolean f;

    @NonNull
    protected final String id;
    protected String pmZoneId;
    protected String testCreativeId;

    public p(@NonNull String str, @NonNull String str2) {
        this.id = str;
        this.adUnitId = str2;
        this.adPosition = v.b.UNKNOWN;
    }

    public Map<String, List<String>> a() {
        return this.a;
    }

    public String b() {
        return this.pmZoneId;
    }

    @NonNull
    public v.b getAdPosition() {
        return this.adPosition;
    }

    @NonNull
    public String getAdUnitId() {
        return this.adUnitId;
    }

    public c getBanner() {
        return this.b;
    }

    public String getCustomData() {
        Map<String, List<String>> mapA = a();
        if (mapA != null && !mapA.isEmpty()) {
            StringBuilder sb = null;
            for (String str : mapA.keySet()) {
                if (sb == null) {
                    sb = new StringBuilder();
                } else {
                    sb.append("|");
                }
                sb.append(str);
                sb.append(SimpleComparison.EQUAL_TO_OPERATION);
                List<String> list = mapA.get(str);
                if (list != null) {
                    int i = 0;
                    for (String str2 : list) {
                        if (i > 0) {
                            sb.append(",");
                        }
                        sb.append(str2);
                        i++;
                    }
                }
            }
            if (sb != null) {
                return sb.toString();
            }
        }
        return null;
    }

    public JSONObject getExtJson(JSONArray jSONArray) throws JSONException {
        try {
            JSONObject jSONObject = new JSONObject();
            if (jSONArray != null) {
                JSONObject jSONObject2 = new JSONObject();
                jSONObject2.putOpt("keywords", jSONArray);
                JSONObject jSONObject3 = new JSONObject();
                jSONObject3.putOpt("pubmatic", jSONObject2);
                jSONObject.putOpt("bidder", jSONObject3);
            }
            if (this.f) {
                jSONObject.putOpt("reward", 1);
            }
            return jSONObject;
        } catch (JSONException unused) {
            POBLog.warn("POBImpression", "Not able to generate Ext Json.", new Object[0]);
            return null;
        }
    }

    @NonNull
    public String getId() {
        return this.id;
    }

    @NonNull
    public JSONObject getImpressionJson() throws JSONException {
        JSONArray jSONArray;
        JSONObject jSONObject = new JSONObject();
        jSONObject.put("id", this.id);
        if (com.pubmatic.sdk.common.i.getSdkConfig().isUseInternalBrowser()) {
            jSONObject.put("clickbrowser", 0);
        } else {
            jSONObject.put("clickbrowser", 1);
        }
        jSONObject.put("displaymanager", "PubMatic_OpenWrap_SDK");
        jSONObject.put("displaymanagerver", "3.7.0");
        jSONObject.put("tagid", this.adUnitId);
        String strB = b();
        if (com.pubmatic.sdk.common.utility.o.isNullOrEmpty(strB)) {
            jSONArray = null;
        } else {
            jSONArray = new JSONArray();
            jSONArray.put(putKeyValueObject("pmZoneId", strB));
        }
        String testCreativeId = getTestCreativeId();
        if (!com.pubmatic.sdk.common.utility.o.isNullOrEmpty(testCreativeId)) {
            if (jSONArray == null) {
                jSONArray = new JSONArray();
            }
            jSONArray.put(putKeyValueObject("testcrid", testCreativeId));
        }
        String customData = getCustomData();
        if (customData != null) {
            if (jSONArray == null) {
                jSONArray = new JSONArray();
            }
            jSONArray.put(putKeyValueObject("dctr", customData));
        }
        JSONObject extJson = getExtJson(jSONArray);
        if (extJson != null && extJson.length() > 0) {
            jSONObject.putOpt("ext", extJson);
        }
        jSONObject.put("secure", com.pubmatic.sdk.common.i.getSdkConfig().isRequestSecureCreative() ? 1 : 0);
        c cVar = this.b;
        if (cVar != null) {
            cVar.setAdPosition(this.adPosition);
            c cVar2 = this.b;
            jSONObject.put(com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_BANNER, cVar2.getRTBJson(cVar2.getSupportedAPIs(), false));
        }
        y yVar = this.c;
        if (yVar != null) {
            yVar.setPosition(this.adPosition);
            jSONObject.put(com.pubmatic.sdk.common.base.c.CREATIVE_TYPE_VIDEO, this.c.getRTBJson());
        }
        jSONObject.put("instl", this.e ? 1 : 0);
        return jSONObject;
    }

    public s getNative() {
        return null;
    }

    public String getTestCreativeId() {
        return this.testCreativeId;
    }

    public y getVideo() {
        return this.c;
    }

    public boolean isInterstitial() {
        return this.e;
    }

    public boolean isRewardedAd() {
        return this.f;
    }

    @NonNull
    public JSONObject putKeyValueObject(String str, Object... objArr) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        try {
            jSONObject.putOpt("key", str);
            jSONObject.putOpt("value", new JSONArray(objArr));
            return jSONObject;
        } catch (JSONException unused) {
            POBLog.warn("POBImpression", "Not able to generate Json with key/value pair.", new Object[0]);
            return jSONObject;
        }
    }

    public void setAdPosition(@NonNull v.b bVar) {
        this.adPosition = bVar;
    }

    public void setBanner(c cVar) {
        this.b = cVar;
    }

    public void setCustomParam(Map<String, List<String>> map) {
        this.a = map;
    }

    public void setInterstitial(boolean z) {
        this.e = z;
    }

    public void setNative(s sVar) {
    }

    public void setPMZoneId(String str) {
        this.pmZoneId = str;
    }

    public void setTestCreativeId(String str) {
        this.testCreativeId = str;
    }

    public void setVideo(y yVar) {
        this.c = yVar;
    }

    public p(@NonNull String str, @NonNull String str2, boolean z, boolean z2) {
        this(str, str2);
        this.f = z;
        this.e = z2;
    }
}
