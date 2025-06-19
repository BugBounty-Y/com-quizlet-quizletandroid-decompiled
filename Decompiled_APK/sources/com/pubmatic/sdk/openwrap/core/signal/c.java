package com.pubmatic.sdk.openwrap.core.signal;

import android.content.Context;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.common.network.i;
import com.pubmatic.sdk.common.utility.o;
import com.pubmatic.sdk.openwrap.core.n;
import com.pubmatic.sdk.openwrap.core.v;
import java.net.URL;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class c implements h {

    @NotNull
    public static final a Companion = new a(null);

    @NotNull
    private final Context a;
    private com.pubmatic.sdk.common.models.f b;
    private v c;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    public c(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
    }

    private final JSONObject a() throws JSONException {
        JSONObject jSONObject = new JSONObject();
        com.pubmatic.sdk.common.models.f fVar = this.b;
        if (fVar != null) {
            try {
                jSONObject.put("geo", c());
                jSONObject.put("mccmnc", fVar.getMccmnc());
                i.a connectionType = com.pubmatic.sdk.common.i.getNetworkMonitor(getContext()).getConnectionType();
                Intrinsics.checkNotNullExpressionValue(connectionType, "getNetworkMonitor(context).getConnectionType()");
                jSONObject.put("connectiontype", connectionType.getValue());
                return jSONObject;
            } catch (JSONException e) {
                POBLog.error("POBALMAXSignalBuilder", Intrinsics.k(e.getMessage(), "Exception occurred in getDeviceObject() : "), new Object[0]);
            }
        }
        return jSONObject;
    }

    private final JSONObject b() throws JSONException {
        JSONObject jSONObject = new JSONObject();
        try {
            JSONObject jSONObject2 = new JSONObject();
            jSONObject2.put("clientconfig", 1);
            jSONObject.put("wrapper", jSONObject2);
            return jSONObject;
        } catch (JSONException e) {
            POBLog.error("POBALMAXSignalBuilder", Intrinsics.k(e.getMessage(), "Exception occurred in getExtObject() : "), new Object[0]);
            return jSONObject;
        }
    }

    private final JSONObject c() throws JSONException {
        JSONObject jSONObject = new JSONObject();
        try {
            com.pubmatic.sdk.common.models.f fVar = this.b;
            if (fVar != null) {
                jSONObject.put("utcoffset", fVar.getTimeZoneOffsetInMinutes());
                return jSONObject;
            }
        } catch (JSONException e) {
            POBLog.error("POBALMAXSignalBuilder", Intrinsics.k(e.getMessage(), "Exception occurred in getGeoObject() : "), new Object[0]);
        }
        return jSONObject;
    }

    @Override // com.pubmatic.sdk.openwrap.core.signal.h
    @NotNull
    public String build() throws JSONException {
        JSONObject jSONObject = new JSONObject();
        try {
            v vVar = this.c;
            if (vVar != null) {
                jSONObject.put("imp", n.getImpressionJsonArray(vVar));
            }
            jSONObject.put("device", a());
            if (com.pubmatic.sdk.common.i.getSdkConfig().getMeasurementProvider("com.pubmatic.sdk.omsdk.POBHTMLMeasurement") != null) {
                jSONObject.put("source", n.getMeasurementJson());
            }
            n nVar = n.INSTANCE;
            JSONObject userJson = n.getUserJson(this.a);
            if (userJson.length() > 0) {
                jSONObject.put("user", userJson);
            }
            JSONObject regsJson = n.getRegsJson(this.a);
            if (!o.isJsonObjectNullOrEmpty(regsJson)) {
                jSONObject.put("regs", regsJson);
            }
            jSONObject.put("ext", b());
            com.pubmatic.sdk.common.models.d applicationInfo = com.pubmatic.sdk.common.i.getSdkConfig().getApplicationInfo();
            if (applicationInfo != null) {
                JSONObject jSONObjectA = a(applicationInfo);
                if (jSONObjectA.length() > 0) {
                    jSONObject.put("app", jSONObjectA);
                }
            }
        } catch (JSONException e) {
            POBLog.error("POBALMAXSignalBuilder", Intrinsics.k(e.getMessage(), "Exception occurred while building signal, reason : "), new Object[0]);
        }
        String string = jSONObject.toString();
        Intrinsics.checkNotNullExpressionValue(string, "ortbJSON.toString()");
        return string;
    }

    @NotNull
    public final Context getContext() {
        return this.a;
    }

    @Override // com.pubmatic.sdk.openwrap.core.signal.h
    public void setDeviceInfo(com.pubmatic.sdk.common.models.f fVar) {
        this.b = fVar;
    }

    @Override // com.pubmatic.sdk.openwrap.core.signal.h
    public void setRequest(v vVar) {
        this.c = vVar;
    }

    private final JSONObject a(com.pubmatic.sdk.common.models.d dVar) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        try {
            n nVar = n.INSTANCE;
            n.addParamToJson(jSONObject, "domain", dVar.getDomain());
            Boolean boolIsPaid = dVar.isPaid();
            if (boolIsPaid != null) {
                jSONObject.put("paid", boolIsPaid.booleanValue() ? 1 : 0);
            }
            if (!o.isNullOrEmpty(dVar.getKeywords())) {
                jSONObject.put("keywords", dVar.getKeywords());
            }
            URL storeURL = dVar.getStoreURL();
            if (storeURL != null) {
                jSONObject.put("storeurl", storeURL.toString());
                return jSONObject;
            }
        } catch (JSONException e) {
            POBLog.error("POBALMAXSignalBuilder", Intrinsics.k(e.getMessage(), "Exception occurred in getAppJson() : "), new Object[0]);
        }
        return jSONObject;
    }
}
