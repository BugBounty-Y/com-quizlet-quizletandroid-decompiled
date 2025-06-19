package com.google.android.gms.internal.ads;

import android.text.TextUtils;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class Yl implements Gq {
    public static final Pattern d = Pattern.compile("([^;]+=[^;]+)(;\\s|$)", 2);
    public final String a;
    public final Pq b;
    public final Tq c;

    public Yl(String str, Tq tq, Pq pq) {
        this.a = str;
        this.c = tq;
        this.b = pq;
    }

    @Override // com.google.android.gms.internal.ads.Gq
    public final Object b(Object obj) throws zzdwf {
        String strJoin;
        zzdwf zzdwfVar;
        JSONObject jSONObject;
        String strConcat;
        Xl xl = (Xl) obj;
        int iOptInt = xl.a.optInt("http_timeout_millis", 60000);
        C1810Zb c1810Zb = xl.b;
        int i = c1810Zb.g;
        Tq tq = this.c;
        Pq pq = this.b;
        strJoin = "";
        if (i != -2) {
            if (i == 1) {
                List list = c1810Zb.a;
                if (list != null) {
                    strJoin = TextUtils.join(", ", list);
                    com.google.android.gms.ads.internal.util.client.i.e(strJoin);
                }
                zzdwfVar = new zzdwf(2, "Error building request URL: ".concat(String.valueOf(strJoin)));
            } else {
                zzdwfVar = new zzdwf(1);
            }
            pq.g(zzdwfVar);
            pq.h(false);
            tq.a(pq);
            throw zzdwfVar;
        }
        HashMap map = new HashMap();
        if (c1810Zb.e) {
            String str = this.a;
            if (!TextUtils.isEmpty(str)) {
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.U0)).booleanValue()) {
                    if (TextUtils.isEmpty(str)) {
                        strConcat = "";
                    } else {
                        Matcher matcher = d.matcher(str);
                        strConcat = "";
                        while (matcher.find()) {
                            String strGroup = matcher.group(1);
                            if (strGroup != null) {
                                Locale locale = Locale.ROOT;
                                if (strGroup.toLowerCase(locale).startsWith("id=") || strGroup.toLowerCase(locale).startsWith("ide=")) {
                                    if (!TextUtils.isEmpty(strConcat)) {
                                        strConcat = strConcat.concat("; ");
                                    }
                                    strConcat = strConcat.concat(strGroup);
                                }
                            }
                        }
                    }
                    if (!TextUtils.isEmpty(strConcat)) {
                        map.put("Cookie", strConcat);
                    }
                } else {
                    map.put("Cookie", str);
                }
            }
        }
        if (c1810Zb.d && (jSONObject = xl.a) != null) {
            JSONObject jSONObjectOptJSONObject = jSONObject.optJSONObject("pii");
            if (jSONObjectOptJSONObject != null) {
                if (!TextUtils.isEmpty(jSONObjectOptJSONObject.optString("doritos", ""))) {
                    map.put("x-afma-drt-cookie", jSONObjectOptJSONObject.optString("doritos", ""));
                }
                if (!TextUtils.isEmpty(jSONObjectOptJSONObject.optString("doritos_v2", ""))) {
                    map.put("x-afma-drt-v2-cookie", jSONObjectOptJSONObject.optString("doritos_v2", ""));
                }
            } else {
                com.google.android.gms.ads.internal.util.A.l("DSID signal does not exist.");
            }
        }
        String str2 = c1810Zb.c;
        strJoin = TextUtils.isEmpty(str2) ? "" : str2;
        pq.h(true);
        tq.a(pq);
        return new Ul(c1810Zb.f, iOptInt, map, strJoin.getBytes(StandardCharsets.UTF_8), "");
    }
}
