package com.pubmatic.sdk.openwrap.core;

import android.content.Context;
import androidx.annotation.NonNull;
import com.amazon.device.ads.DtbDeviceData;
import com.appsflyer.AdRevenueScheme;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.common.models.h;
import com.pubmatic.sdk.common.network.a;
import com.quizlet.db.data.models.base.AssociationNames;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import java.util.HashMap;
import java.util.UUID;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class w implements com.pubmatic.sdk.common.base.n {

    @NonNull
    private final String a;

    @NonNull
    private final v b;

    @NonNull
    private final Context c;
    private final Boolean d;
    private com.pubmatic.sdk.common.utility.g e;
    private com.pubmatic.sdk.common.models.f f;
    private com.pubmatic.sdk.common.models.c g;

    public w(@NonNull v vVar, @NonNull String str, @NonNull Context context) {
        this.c = context.getApplicationContext();
        this.a = str;
        this.b = vVar;
        this.d = Boolean.valueOf((context.getApplicationInfo().flags & 2) != 0);
    }

    private JSONObject a() throws JSONException {
        JSONObject jSONObject = new JSONObject();
        try {
            JSONObject jSONObject2 = new JSONObject();
            jSONObject2.put("profileid", this.b.getProfileId());
            if (this.d.booleanValue() && this.b.getVersionId() != null) {
                jSONObject2.put("versionid", this.b.getVersionId());
            }
            if (!this.b.a()) {
                jSONObject2.put("sumry_disable", 1);
            }
            jSONObject2.put("clientconfig", 1);
            jSONObject.put("wrapper", jSONObject2);
            return jSONObject;
        } catch (JSONException e) {
            POBLog.error("POBRequestBuilder", "Exception occurred in getExtObject() : " + e.getMessage(), new Object[0]);
            return jSONObject;
        }
    }

    private JSONObject b() throws JSONException {
        int accuracy;
        JSONObject jSONObject = new JSONObject();
        try {
            com.pubmatic.sdk.common.models.k userInfo = com.pubmatic.sdk.common.i.getSdkConfig().getUserInfo();
            if (userInfo != null) {
                n nVar = n.INSTANCE;
                n.addParamToJson(jSONObject, "region", userInfo.getRegion());
                n.addParamToJson(jSONObject, "city", userInfo.getCity());
                n.addParamToJson(jSONObject, "metro", userInfo.getMetro());
                n.addParamToJson(jSONObject, "zip", userInfo.getZip());
                com.pubmatic.sdk.common.models.f fVar = this.f;
                if (fVar != null) {
                    n.addParamToJson(jSONObject, AdRevenueScheme.COUNTRY, fVar.getISOAlpha3CountryCode());
                }
            }
            com.pubmatic.sdk.common.models.h location = com.pubmatic.sdk.common.utility.o.getLocation(this.e);
            if (location != null) {
                h.a source = location.getSource();
                if (source != null) {
                    jSONObject.put(DBUserFields.Names.USER_UPGRADE_TYPE, source.getValue());
                }
                jSONObject.put("lat", location.getLatitude());
                jSONObject.put("lon", location.getLongitude());
                if (location.getSource() == h.a.GPS && (accuracy = (int) location.getAccuracy()) > 0) {
                    jSONObject.put("accuracy", accuracy);
                }
                long lastFixInMillis = location.getLastFixInMillis();
                if (lastFixInMillis > 0) {
                    jSONObject.put("lastfix", lastFixInMillis / 1000);
                }
            }
            com.pubmatic.sdk.common.models.f fVar2 = this.f;
            if (fVar2 != null) {
                jSONObject.put("utcoffset", fVar2.getTimeZoneOffsetInMinutes());
                return jSONObject;
            }
        } catch (Exception e) {
            POBLog.error("POBRequestBuilder", "Exception occurred in getGeoObject() : " + e.getMessage(), new Object[0]);
        }
        return jSONObject;
    }

    @NonNull
    private String c() {
        String adServerUrl = this.b.getAdServerUrl();
        if (adServerUrl == null) {
            adServerUrl = this.a;
        }
        return this.b.isDebugStateEnabled() ? com.pubmatic.sdk.common.utility.o.buildUrlWithQueryParam(adServerUrl, "debug", "1") : adServerUrl;
    }

    private void d() {
        com.pubmatic.sdk.common.models.f fVar = this.f;
        if (fVar != null) {
            fVar.updateAdvertisingIdInfo();
        }
    }

    @Override // com.pubmatic.sdk.common.base.n
    public com.pubmatic.sdk.common.network.a build() {
        return prepareHttpRequest(c(), getBody().toString(), "2.5");
    }

    public JSONObject getAppJson(String str) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        try {
            com.pubmatic.sdk.common.models.c cVar = this.g;
            if (cVar != null) {
                n nVar = n.INSTANCE;
                n.addParamToJson(jSONObject, "name", cVar.getAppName());
                n.addParamToJson(jSONObject, "bundle", this.g.getPackageName());
            }
            com.pubmatic.sdk.common.models.d applicationInfo = com.pubmatic.sdk.common.i.getSdkConfig().getApplicationInfo();
            if (applicationInfo != null) {
                n nVar2 = n.INSTANCE;
                n.addParamToJson(jSONObject, "domain", applicationInfo.getDomain());
                if (applicationInfo.getStoreURL() != null) {
                    n.addParamToJson(jSONObject, "storeurl", applicationInfo.getStoreURL().toString());
                } else {
                    POBLog.warn("POBRequestBuilder", "Missing \"storeURL\" in the request. It is required for platform identification", new Object[0]);
                }
                Boolean boolIsPaid = applicationInfo.isPaid();
                if (boolIsPaid != null) {
                    jSONObject.put("paid", boolIsPaid.booleanValue() ? 1 : 0);
                }
                if (applicationInfo.getCategories() != null) {
                    jSONObject.put("cat", new JSONArray(applicationInfo.getCategories().split(",")));
                }
                if (!com.pubmatic.sdk.common.utility.o.isNullOrEmpty(applicationInfo.getKeywords())) {
                    jSONObject.put("keywords", applicationInfo.getKeywords());
                }
            }
            com.pubmatic.sdk.common.models.c cVar2 = this.g;
            if (cVar2 != null) {
                jSONObject.put("ver", cVar2.getAppVersion());
            }
            JSONObject jSONObject2 = new JSONObject();
            jSONObject2.put("id", str);
            jSONObject.put(AssociationNames.PUBLISHER, jSONObject2);
            return jSONObject;
        } catch (JSONException e) {
            POBLog.error("POBRequestBuilder", "Exception occurred in getAppJson() : " + e.getMessage(), new Object[0]);
            return jSONObject;
        }
    }

    public JSONObject getBody() throws JSONException {
        d();
        JSONObject jSONObject = new JSONObject();
        try {
            jSONObject.put("id", UUID.randomUUID().toString());
            jSONObject.put("at", 1);
            jSONObject.put("cur", n.getCurrencyJson());
            jSONObject.put("imp", n.getImpressionJsonArray(this.b));
            jSONObject.put("app", getAppJson(this.b.getPubId()));
            jSONObject.put("device", getDeviceObject());
            if (com.pubmatic.sdk.common.i.getSdkConfig().getMeasurementProvider("com.pubmatic.sdk.omsdk.POBHTMLMeasurement") != null) {
                jSONObject.put("source", n.getMeasurementJson());
            }
            JSONObject userJson = n.getUserJson(this.c);
            if (userJson.length() > 0) {
                jSONObject.put("user", userJson);
            }
            if (this.b.getTestMode() != null && this.b.getTestMode().booleanValue()) {
                jSONObject.put("test", 1);
            }
            JSONObject regsJson = n.getRegsJson(this.c);
            if (regsJson != null && regsJson.length() > 0) {
                jSONObject.put("regs", regsJson);
            }
            jSONObject.put("ext", a());
            return jSONObject;
        } catch (JSONException e) {
            POBLog.error("POBRequestBuilder", "Exception occurred in getBody() : " + e.getMessage(), new Object[0]);
            return jSONObject;
        }
    }

    public JSONObject getDeviceObject() throws JSONException {
        JSONObject jSONObject = new JSONObject();
        if (this.f != null) {
            try {
                jSONObject.put("geo", b());
                jSONObject.put("pxratio", this.f.getPxratio());
                jSONObject.put("mccmnc", this.f.getMccmnc());
                if (this.f.getLmtEnabled() != null) {
                    jSONObject.put("lmt", this.f.getLmtEnabled().booleanValue() ? 1 : 0);
                }
                String advertisingID = this.f.getAdvertisingID();
                if (com.pubmatic.sdk.common.i.getSdkConfig().isAllowAdvertisingId() && advertisingID != null) {
                    jSONObject.put("ifa", advertisingID);
                }
                jSONObject.put("connectiontype", com.pubmatic.sdk.common.i.getNetworkMonitor(this.c).getConnectionType().getValue());
                n nVar = n.INSTANCE;
                n.addParamToJson(jSONObject, "carrier", this.f.getCarrierName());
                jSONObject.put("js", 1);
                jSONObject.put("ua", this.f.getUserAgent());
                jSONObject.put("make", this.f.getMake());
                jSONObject.put(DtbDeviceData.DEVICE_DATA_MODEL_KEY, this.f.getModel());
                jSONObject.put("os", this.f.getOsName());
                jSONObject.put("osv", this.f.getOsVersion());
                jSONObject.put("h", this.f.getScreenHeight());
                jSONObject.put("w", this.f.getScreenWidth());
                jSONObject.put("language", this.f.getAcceptLanguage());
                if (com.pubmatic.sdk.common.utility.o.isTablet(this.c)) {
                    jSONObject.put("devicetype", 5);
                    return jSONObject;
                }
                jSONObject.put("devicetype", 4);
                return jSONObject;
            } catch (Exception e) {
                POBLog.error("POBRequestBuilder", "Exception occurred in getDeviceObject() : " + e.getMessage(), new Object[0]);
            }
        }
        return jSONObject;
    }

    @NonNull
    public com.pubmatic.sdk.common.network.a prepareHttpRequest(@NonNull String str, @NonNull String str2, String str3) {
        HashMap map = new HashMap();
        map.put("Content-Type", "application/json");
        if (str3 != null) {
            map.put("x-openrtb-version", str3);
        }
        com.pubmatic.sdk.common.network.a aVar = new com.pubmatic.sdk.common.network.a();
        aVar.setRequestMethod(a.EnumC0011a.POST);
        aVar.setPostData(str2);
        aVar.setUrl(str);
        aVar.setTimeout(this.b.getNetworkTimeout() * 1000);
        aVar.setRequestTag(String.valueOf(hashCode()));
        aVar.setHeaders(map);
        return aVar;
    }

    @Override // com.pubmatic.sdk.common.base.n
    public void setAppInfo(com.pubmatic.sdk.common.models.c cVar) {
        this.g = cVar;
    }

    @Override // com.pubmatic.sdk.common.base.n
    public void setDeviceInfo(com.pubmatic.sdk.common.models.f fVar) {
        this.f = fVar;
    }

    @Override // com.pubmatic.sdk.common.base.n
    public void setLocationDetector(com.pubmatic.sdk.common.utility.g gVar) {
        this.e = gVar;
    }
}
