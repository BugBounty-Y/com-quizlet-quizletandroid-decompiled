package com.pubmatic.sdk.openwrap.core;

import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.openwrap.core.v;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class c {
    private com.pubmatic.sdk.common.f[] a;
    private v.b b;

    public c(com.pubmatic.sdk.common.f... fVarArr) {
        this.a = fVarArr;
        this.b = v.b.UNKNOWN;
    }

    @NonNull
    public JSONObject getRTBJson(@NonNull Set<Integer> set, boolean z) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        v.b bVar = this.b;
        if (bVar != null) {
            jSONObject.put("pos", bVar.getValue());
        }
        com.pubmatic.sdk.common.f[] fVarArr = this.a;
        if (fVarArr != null) {
            jSONObject.put("format", getSizeArray(fVarArr));
        }
        if (!set.isEmpty()) {
            jSONObject.put("api", new JSONArray((Collection) set));
        }
        if (z) {
            jSONObject.put("vcm", 1);
            if (v.b.FULL_SCREEN.equals(this.b)) {
                jSONObject.put("api", new JSONArray((Collection) getSupportedAPIs()));
            }
        }
        return jSONObject;
    }

    public JSONArray getSizeArray(@NonNull com.pubmatic.sdk.common.f... fVarArr) throws JSONException {
        JSONArray jSONArray = new JSONArray();
        for (com.pubmatic.sdk.common.f fVar : fVarArr) {
            if (fVar != null) {
                JSONObject jSONObject = new JSONObject();
                try {
                    jSONObject.put("w", fVar.getAdWidth());
                    jSONObject.put("h", fVar.getAdHeight());
                    jSONArray.put(jSONObject);
                } catch (JSONException unused) {
                    POBLog.error("POBBanner", "Error on formatting width/height in ad request.", new Object[0]);
                }
            }
        }
        return jSONArray;
    }

    @NonNull
    public Set<Integer> getSupportedAPIs() {
        HashSet hashSet = new HashSet();
        hashSet.add(Integer.valueOf(v.a.MRAID2.getValue()));
        hashSet.add(Integer.valueOf(v.a.MRAID3.getValue()));
        if (com.pubmatic.sdk.common.i.getSdkConfig().getMeasurementProvider("com.pubmatic.sdk.omsdk.POBHTMLMeasurement") != null) {
            hashSet.add(Integer.valueOf(v.a.OMSDK.getValue()));
        }
        return hashSet;
    }

    public void setAdPosition(v.b bVar) {
        this.b = bVar;
    }

    public void setAdSizes(com.pubmatic.sdk.common.f... fVarArr) {
        this.a = fVarArr;
    }

    public c() {
    }
}
