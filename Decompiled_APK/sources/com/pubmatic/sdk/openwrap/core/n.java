package com.pubmatic.sdk.openwrap.core;

import android.content.Context;
import com.amazon.device.ads.DtbConstants;
import com.onetrust.otpublishers.headless.Public.Keys.OTGppKeys;
import com.onetrust.otpublishers.headless.Public.Keys.OTIABCCPAKeys;
import com.onetrust.otpublishers.headless.Public.uiutils.OTVendorUtils;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.common.models.k;
import java.util.List;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class n {

    @NotNull
    public static final n INSTANCE = new n();

    @NotNull
    public static final String TAG = "POBCommonOrtbJsonHelper";

    private n() {
    }

    private final void a(JSONObject jSONObject) throws JSONException {
        Boolean boolIsCoppa = com.pubmatic.sdk.common.i.getSdkConfig().isCoppa();
        if (boolIsCoppa == null) {
            return;
        }
        jSONObject.put("coppa", boolIsCoppa.booleanValue() ? 1 : 0);
    }

    public static final void addParamToJson(JSONObject jSONObject, @NotNull String key, String str) {
        Intrinsics.checkNotNullParameter(key, "key");
        if (jSONObject == null || com.pubmatic.sdk.common.utility.o.isNullOrEmpty(str)) {
            return;
        }
        try {
            jSONObject.put(key, str);
        } catch (JSONException unused) {
            POBLog.warn(TAG, "Unable to add " + key + " and " + ((Object) str), new Object[0]);
        }
    }

    private final void b(Context context, JSONObject jSONObject) throws JSONException {
        Integer integerFromSharedPreference = com.pubmatic.sdk.common.utility.j.getIntegerFromSharedPreference(context, "IABTCF_gdprApplies");
        if (integerFromSharedPreference == null) {
            return;
        }
        jSONObject.put("gdpr", integerFromSharedPreference.intValue());
    }

    private final void c(com.pubmatic.sdk.common.models.e eVar, JSONObject jSONObject) throws JSONException {
        Map<String, com.pubmatic.sdk.common.models.j> segments = eVar.getSegments();
        Intrinsics.checkNotNullExpressionValue(segments, "dataProvider.segments");
        if (segments.isEmpty()) {
            return;
        }
        JSONArray jSONArray = new JSONArray();
        for (com.pubmatic.sdk.common.models.j jVar : segments.values()) {
            JSONObject jSONObject2 = new JSONObject();
            jSONObject2.put("id", jVar.getSegId());
            String name = jVar.getName();
            if (name != null) {
                if (name.length() <= 0) {
                    name = null;
                }
                if (name != null) {
                    jSONObject2.put("name", name);
                }
            }
            String value = jVar.getValue();
            if (value != null) {
                String str = value.length() > 0 ? value : null;
                if (str != null) {
                    jSONObject2.put("value", str);
                }
            }
            jSONArray.put(jSONObject2);
        }
        if (jSONArray.length() > 0) {
            jSONObject.put("segment", jSONArray);
        }
    }

    private final void d(Context context, JSONObject jSONObject) throws JSONException {
        String stringFromSharedPreference = com.pubmatic.sdk.common.utility.j.getStringFromSharedPreference(context, OTGppKeys.IAB_GPP_HDR_GPP_STRING, null);
        if (com.pubmatic.sdk.common.utility.o.isNullOrEmpty(stringFromSharedPreference)) {
            return;
        }
        jSONObject.put("gpp", stringFromSharedPreference);
    }

    private final void e(Context context, JSONObject jSONObject) throws JSONException {
        String stringFromSharedPreference = com.pubmatic.sdk.common.utility.j.getStringFromSharedPreference(context, OTGppKeys.IAB_GPP_GPP_SID, null);
        if (stringFromSharedPreference == null) {
            return;
        }
        JSONArray jSONArray = new JSONArray();
        for (String str : StringsKt__StringsKt.split$default(stringFromSharedPreference, new String[]{"_"}, false, 0, 6, null)) {
            try {
                jSONArray.put(Integer.parseInt(str));
            } catch (NumberFormatException unused) {
                POBLog.warn(TAG, "Invalid GPP_SID value is passed: %s", str);
            }
        }
        if (jSONArray.length() > 0) {
            jSONObject.put("gpp_sid", jSONArray);
        }
    }

    @NotNull
    public static final JSONArray getCurrencyJson() {
        JSONArray jSONArrayPut = new JSONArray().put("USD");
        Intrinsics.checkNotNullExpressionValue(jSONArrayPut, "JSONArray().put(\"USD\")");
        return jSONArrayPut;
    }

    @NotNull
    public static final JSONArray getImpressionJsonArray(@NotNull v request) {
        Intrinsics.checkNotNullParameter(request, "request");
        JSONArray jSONArray = new JSONArray();
        p[] impressions = request.getImpressions();
        if (impressions != null) {
            int length = impressions.length;
            int i = 0;
            while (i < length) {
                p pVar = impressions[i];
                i++;
                try {
                    jSONArray.put(pVar.getImpressionJson());
                } catch (JSONException e) {
                    POBLog.error(TAG, Intrinsics.k(e.getMessage(), "Exception occurred in getImpressionJson(): "), new Object[0]);
                }
            }
        }
        return jSONArray;
    }

    public static final JSONObject getMeasurementJson() throws JSONException {
        try {
            JSONObject jSONObject = new JSONObject();
            jSONObject.putOpt("omidpn", "Pubmatic");
            jSONObject.putOpt("omidpv", "3.7.0");
            return new JSONObject().putOpt("ext", jSONObject);
        } catch (JSONException e) {
            POBLog.error(TAG, Intrinsics.k(e.getMessage(), "Exception occurred in getMeasurementParam() : "), new Object[0]);
            return null;
        }
    }

    public static final JSONObject getRegsJson(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        try {
            JSONObject jSONObject = new JSONObject();
            n nVar = INSTANCE;
            nVar.a(jSONObject);
            JSONObject jSONObject2 = new JSONObject();
            nVar.b(context, jSONObject2);
            nVar.a(context, jSONObject2);
            nVar.d(context, jSONObject2);
            nVar.e(context, jSONObject2);
            if (jSONObject2.length() != 0) {
                jSONObject.put("ext", jSONObject2);
            }
            return jSONObject;
        } catch (JSONException e) {
            POBLog.error(TAG, Intrinsics.k(e.getMessage(), "Exception occurred in getRegsJson() : "), new Object[0]);
            return null;
        }
    }

    @NotNull
    public static final JSONObject getUserJson(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        JSONObject jSONObject = new JSONObject();
        try {
            com.pubmatic.sdk.common.models.k userInfo = com.pubmatic.sdk.common.i.getSdkConfig().getUserInfo();
            if (userInfo != null) {
                k.a gender = userInfo.getGender();
                int i = gender == null ? -1 : m.$EnumSwitchMapping$0[gender.ordinal()];
                if (i == 1) {
                    jSONObject.put("gender", "M");
                } else if (i == 2) {
                    jSONObject.put("gender", "F");
                } else if (i == 3) {
                    jSONObject.put("gender", "O");
                }
                if (userInfo.getBirthYear() > 0) {
                    jSONObject.put("yob", userInfo.getBirthYear());
                }
                if (!com.pubmatic.sdk.common.utility.o.isNullOrEmpty(userInfo.getKeywords())) {
                    jSONObject.put("keywords", userInfo.getKeywords());
                }
                JSONArray jSONArrayA = a(userInfo);
                if (jSONArrayA.length() > 0) {
                    jSONObject.put("data", jSONArrayA);
                }
            }
            JSONObject jSONObjectA = INSTANCE.a(context);
            if (jSONObjectA.length() > 0) {
                jSONObject.put("ext", jSONObjectA);
            }
            return jSONObject;
        } catch (JSONException e) {
            POBLog.error(TAG, Intrinsics.k(e.getMessage(), "Exception occurred in getUserJson() : "), new Object[0]);
            return jSONObject;
        }
    }

    private final void a(Context context, JSONObject jSONObject) throws JSONException {
        String stringFromSharedPreference = com.pubmatic.sdk.common.utility.j.getStringFromSharedPreference(context, OTIABCCPAKeys.OT_IAB_US_PRIVACY_STRING, null);
        if (com.pubmatic.sdk.common.utility.o.isNullOrEmpty(stringFromSharedPreference)) {
            return;
        }
        jSONObject.put(DtbConstants.APS_ADMOB_CONST_CCPA_US_PRIVACY, stringFromSharedPreference);
    }

    private final void b(com.pubmatic.sdk.common.models.e eVar, JSONObject jSONObject) throws JSONException {
        JSONObject jSONObject2 = new JSONObject();
        JSONObject ext = eVar.getExt();
        if (ext != null) {
            jSONObject2 = ext;
        }
        if (eVar.getSegTax() > 0) {
            jSONObject2.put("segtax", eVar.getSegTax());
        }
        if (jSONObject2.length() > 0) {
            jSONObject.put("ext", jSONObject2);
        }
    }

    private static final JSONArray a(com.pubmatic.sdk.common.models.k kVar) {
        JSONArray jSONArray = new JSONArray();
        try {
            List<com.pubmatic.sdk.common.models.e> dataProviders = kVar.getDataProviders();
            Intrinsics.checkNotNullExpressionValue(dataProviders, "userInfo.getDataProviders()");
            for (com.pubmatic.sdk.common.models.e dataProvider : dataProviders) {
                JSONObject jSONObject = new JSONObject();
                n nVar = INSTANCE;
                Intrinsics.checkNotNullExpressionValue(dataProvider, "dataProvider");
                nVar.a(dataProvider, jSONObject);
                nVar.c(dataProvider, jSONObject);
                nVar.b(dataProvider, jSONObject);
                jSONArray.put(jSONObject);
            }
        } catch (JSONException e) {
            POBLog.error(TAG, Intrinsics.k(e.getMessage(), "Exception occurred in getUserDataJson() : "), new Object[0]);
        }
        return jSONArray;
    }

    private final void b(JSONObject jSONObject) throws JSONException {
        Map<String, List<com.pubmatic.sdk.common.models.g>> externalUserIds = com.pubmatic.sdk.common.i.getSdkConfig().getExternalUserIds();
        Intrinsics.checkNotNullExpressionValue(externalUserIds, "getSdkConfig().externalUserIds");
        JSONArray jSONArray = new JSONArray();
        if (externalUserIds.isEmpty()) {
            externalUserIds = null;
        }
        if (externalUserIds != null) {
            for (Map.Entry<String, List<com.pubmatic.sdk.common.models.g>> entry : externalUserIds.entrySet()) {
                String key = entry.getKey();
                List<com.pubmatic.sdk.common.models.g> value = entry.getValue();
                JSONObject jSONObject2 = new JSONObject();
                jSONObject2.put("source", key);
                n nVar = INSTANCE;
                Intrinsics.checkNotNullExpressionValue(value, "value");
                jSONObject2.put("uids", nVar.a(value));
                jSONArray.put(jSONObject2);
            }
        }
        if (jSONArray.length() > 0) {
            jSONObject.put("eids", jSONArray);
        }
    }

    private final void a(com.pubmatic.sdk.common.models.e eVar, JSONObject jSONObject) throws JSONException {
        String id = eVar.getId();
        if (id != null) {
            if (id.length() <= 0) {
                id = null;
            }
            if (id != null) {
                jSONObject.put("id", id);
            }
        }
        jSONObject.put("name", eVar.getName());
    }

    private final void c(Context context, JSONObject jSONObject) throws JSONException {
        String stringFromSharedPreference = com.pubmatic.sdk.common.utility.j.getStringFromSharedPreference(context, "IABTCF_TCString", null);
        if (com.pubmatic.sdk.common.utility.o.isNullOrEmpty(stringFromSharedPreference)) {
            return;
        }
        jSONObject.put(OTVendorUtils.CONSENT_TYPE, stringFromSharedPreference);
    }

    private final JSONObject a(Context context) {
        JSONObject jSONObject = new JSONObject();
        try {
            c(context, jSONObject);
            b(jSONObject);
            POBLog.debug(TAG, jSONObject.toString(), new Object[0]);
            return jSONObject;
        } catch (JSONException e) {
            POBLog.error(TAG, Intrinsics.k(e.getMessage(), "Exception occurred in getUserExtJson() : "), new Object[0]);
            return jSONObject;
        }
    }

    private final JSONArray a(List<? extends com.pubmatic.sdk.common.models.g> list) throws JSONException {
        JSONArray jSONArray = new JSONArray();
        for (com.pubmatic.sdk.common.models.g gVar : list) {
            JSONObject jSONObject = new JSONObject();
            jSONObject.put("id", gVar.getId());
            if (gVar.getAtype() > 0) {
                jSONObject.put("atype", gVar.getAtype());
            }
            JSONObject extension = gVar.getExtension();
            if (extension != null) {
                if (extension.length() == 0) {
                    extension = null;
                }
                if (extension != null) {
                    jSONObject.put("ext", extension);
                }
            }
            jSONArray.put(jSONObject);
        }
        return jSONArray;
    }
}
