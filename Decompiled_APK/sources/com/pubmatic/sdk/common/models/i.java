package com.pubmatic.sdk.common.models;

import androidx.annotation.NonNull;
import com.google.ads.mediation.AbstractAdViewAdapter;
import com.pubmatic.sdk.common.utility.o;
import java.util.Set;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class i {
    public static final String COUNTRY_FILTERING_ALLOW_MODE = "include";
    public static final String COUNTRY_FILTERING_BLOCK_MODE = "exclude";
    private int a;
    private int b;
    private int c;
    private final long d = System.currentTimeMillis();
    private String e;
    private Set<String> f;
    private String g;

    public static i build(@NonNull JSONObject jSONObject) throws JSONException {
        i iVar = new i();
        iVar.a = jSONObject.optInt("pid");
        iVar.b = jSONObject.optInt(AbstractAdViewAdapter.AD_UNIT_ID_PARAMETER);
        iVar.c = jSONObject.optInt("pdvid");
        iVar.e = jSONObject.optString("adserver");
        JSONObject jSONObjectOptJSONObject = jSONObject.optJSONObject("ctFiltering");
        if (jSONObjectOptJSONObject != null && jSONObjectOptJSONObject.length() > 0) {
            iVar.g = jSONObjectOptJSONObject.optString("mode");
            iVar.f = o.parseJsonArrayToSet(jSONObjectOptJSONObject.optJSONArray("codes"));
        }
        return iVar;
    }

    public String getAdServerName() {
        return this.e;
    }

    public String getCountryFilteringMode() {
        return this.g;
    }

    public long getCreatedDateTime() {
        return this.d;
    }

    public Set<String> getFilteringCountries() {
        return this.f;
    }

    public int getProfileId() {
        return this.a;
    }

    public int getPublisherId() {
        return this.b;
    }

    public int getVersionId() {
        return this.c;
    }

    public boolean isProfileInfoExpired() {
        return System.currentTimeMillis() - this.d > 86400000;
    }
}
