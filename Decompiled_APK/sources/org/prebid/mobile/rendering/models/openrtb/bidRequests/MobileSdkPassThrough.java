package org.prebid.mobile.rendering.models.openrtb.bidRequests;

import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.prebid.mobile.LogUtil;
import org.prebid.mobile.PrebidMobile;
import org.prebid.mobile.api.data.Position;
import org.prebid.mobile.configuration.AdUnitConfiguration;

/* loaded from: classes3.dex */
public class MobileSdkPassThrough {
    public Boolean a;
    public Integer b;
    public Integer c;
    public Double d;
    public Double e;
    public Position f;
    public Position g;
    public final Integer h;
    public final Integer i;
    public final JSONObject j;

    private MobileSdkPassThrough() {
        this.h = 0;
        this.i = 0;
    }

    public static MobileSdkPassThrough a(MobileSdkPassThrough mobileSdkPassThrough, AdUnitConfiguration adUnitConfiguration) {
        if (mobileSdkPassThrough == null) {
            mobileSdkPassThrough = new MobileSdkPassThrough();
        }
        if (mobileSdkPassThrough.a == null) {
            mobileSdkPassThrough.a = Boolean.valueOf(adUnitConfiguration.a);
        }
        if (mobileSdkPassThrough.b == null) {
            mobileSdkPassThrough.b = Integer.valueOf(adUnitConfiguration.g);
        }
        if (mobileSdkPassThrough.c == null) {
            mobileSdkPassThrough.c = Integer.valueOf(adUnitConfiguration.d);
        }
        if (mobileSdkPassThrough.e == null) {
            mobileSdkPassThrough.e = Double.valueOf(adUnitConfiguration.f);
        }
        if (mobileSdkPassThrough.g == null) {
            mobileSdkPassThrough.g = adUnitConfiguration.j;
        }
        if (mobileSdkPassThrough.d == null) {
            mobileSdkPassThrough.d = Double.valueOf(adUnitConfiguration.e);
        }
        if (mobileSdkPassThrough.f == null) {
            mobileSdkPassThrough.f = adUnitConfiguration.i;
        }
        return mobileSdkPassThrough;
    }

    public static MobileSdkPassThrough b(MobileSdkPassThrough mobileSdkPassThrough, MobileSdkPassThrough mobileSdkPassThrough2) {
        if (mobileSdkPassThrough == null && mobileSdkPassThrough2 == null) {
            return null;
        }
        if (mobileSdkPassThrough == null) {
            return mobileSdkPassThrough2;
        }
        if (mobileSdkPassThrough2 != null) {
            if (mobileSdkPassThrough.a == null) {
                mobileSdkPassThrough.a = mobileSdkPassThrough2.a;
            }
            if (mobileSdkPassThrough.b == null) {
                mobileSdkPassThrough.b = mobileSdkPassThrough2.b;
            }
            if (mobileSdkPassThrough.c == null) {
                mobileSdkPassThrough.c = mobileSdkPassThrough2.c;
            }
            if (mobileSdkPassThrough.d == null) {
                mobileSdkPassThrough.d = mobileSdkPassThrough2.d;
            }
            if (mobileSdkPassThrough.e == null) {
                mobileSdkPassThrough.e = mobileSdkPassThrough2.e;
            }
            if (mobileSdkPassThrough.f == null) {
                mobileSdkPassThrough.f = mobileSdkPassThrough2.f;
            }
            if (mobileSdkPassThrough.g == null) {
                mobileSdkPassThrough.g = mobileSdkPassThrough2.g;
            }
        }
        return mobileSdkPassThrough;
    }

    public static MobileSdkPassThrough c(JSONObject jSONObject) throws JSONException {
        try {
            if (!jSONObject.has("prebid")) {
                return null;
            }
            JSONObject jSONObject2 = jSONObject.getJSONObject("prebid");
            if (!jSONObject2.has("passthrough")) {
                return null;
            }
            JSONArray jSONArray = jSONObject2.getJSONArray("passthrough");
            for (int i = 0; i < jSONArray.length(); i++) {
                JSONObject jSONObject3 = jSONArray.getJSONObject(i);
                if (jSONObject3.has(DBUserFields.Names.USER_UPGRADE_TYPE) && jSONObject3.getString(DBUserFields.Names.USER_UPGRADE_TYPE).equals("prebidmobilesdk") && (jSONObject3.has("adconfiguration") || jSONObject3.has("sdkconfiguration"))) {
                    return new MobileSdkPassThrough(jSONObject3);
                }
            }
            return null;
        } catch (JSONException unused) {
            LogUtil.b("MobileSdkPassThrough", "Can't parse json");
            return null;
        }
    }

    public MobileSdkPassThrough(JSONObject jSONObject) throws JSONException {
        this.h = 0;
        this.i = 0;
        try {
            if (jSONObject.has("adconfiguration")) {
                JSONObject jSONObject2 = jSONObject.getJSONObject("adconfiguration");
                this.j = jSONObject2;
                try {
                    if (jSONObject2.has("ismuted")) {
                        this.a = (Boolean) Boolean.class.cast(jSONObject2.get("ismuted"));
                    }
                } catch (JSONException unused) {
                    LogUtil.b("MobileSdkPassThrough", "Object ismuted has wrong type!");
                }
                JSONObject jSONObject3 = this.j;
                try {
                    if (jSONObject3.has("maxvideoduration")) {
                        this.b = (Integer) Integer.class.cast(jSONObject3.get("maxvideoduration"));
                    }
                } catch (JSONException unused2) {
                    LogUtil.b("MobileSdkPassThrough", "Object maxvideoduration has wrong type!");
                }
                JSONObject jSONObject4 = this.j;
                try {
                    if (jSONObject4.has("skipdelay")) {
                        this.c = (Integer) Integer.class.cast(jSONObject4.get("skipdelay"));
                    }
                } catch (JSONException unused3) {
                    LogUtil.b("MobileSdkPassThrough", "Object skipdelay has wrong type!");
                }
                JSONObject jSONObject5 = this.j;
                try {
                    if (jSONObject5.has("closebuttonarea")) {
                        this.d = (Double) Double.class.cast(jSONObject5.get("closebuttonarea"));
                    }
                } catch (JSONException unused4) {
                    LogUtil.b("MobileSdkPassThrough", "Object closebuttonarea has wrong type!");
                }
                JSONObject jSONObject6 = this.j;
                try {
                    if (jSONObject6.has("skipbuttonarea")) {
                        this.e = (Double) Double.class.cast(jSONObject6.get("skipbuttonarea"));
                    }
                } catch (JSONException unused5) {
                    LogUtil.b("MobileSdkPassThrough", "Object skipbuttonarea has wrong type!");
                }
                JSONObject jSONObject7 = this.j;
                try {
                    if (jSONObject7.has("closebuttonposition")) {
                        this.f = Position.a((String) String.class.cast(jSONObject7.get("closebuttonposition")));
                    }
                } catch (JSONException unused6) {
                    LogUtil.b("MobileSdkPassThrough", "Object closebuttonposition has wrong type!");
                }
                JSONObject jSONObject8 = this.j;
                try {
                    if (jSONObject8.has("skipbuttonposition")) {
                        this.g = Position.a((String) String.class.cast(jSONObject8.get("skipbuttonposition")));
                    }
                } catch (JSONException unused7) {
                    LogUtil.b("MobileSdkPassThrough", "Object skipbuttonposition has wrong type!");
                }
            }
        } catch (JSONException unused8) {
            LogUtil.b("MobileSdkPassThrough", "Can't parse adconfiguration");
        }
        try {
            if (jSONObject.has("sdkconfiguration")) {
                JSONObject jSONObject9 = jSONObject.getJSONObject("sdkconfiguration");
                this.j = jSONObject9;
                if (jSONObject9.has("cftbanner")) {
                    JSONObject jSONObject10 = this.j;
                    try {
                        if (jSONObject10.has("cftbanner")) {
                            this.h = (Integer) Integer.class.cast(jSONObject10.get("cftbanner"));
                        }
                    } catch (JSONException unused9) {
                        LogUtil.b("MobileSdkPassThrough", "Object cftbanner has wrong type!");
                    }
                }
                if (jSONObject9.has("cftprerender")) {
                    JSONObject jSONObject11 = this.j;
                    try {
                        if (jSONObject11.has("cftprerender")) {
                            this.i = (Integer) Integer.class.cast(jSONObject11.get("cftprerender"));
                        }
                    } catch (JSONException unused10) {
                        LogUtil.b("MobileSdkPassThrough", "Object cftprerender has wrong type!");
                    }
                }
                this.h.getClass();
                this.i.getClass();
                int i = PrebidMobile.a;
            }
        } catch (JSONException unused11) {
            LogUtil.b("MobileSdkPassThrough", "Can't parse sdkconfiguration");
        }
    }
}
