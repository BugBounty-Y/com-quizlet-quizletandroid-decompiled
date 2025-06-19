package com.google.android.gms.internal.ads;

import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.Ce, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC1675Ce {
    public static final Pattern a = Pattern.compile("^\\uFEFF?\\s*(\\s*<!--([^-]|(?!-->))*-->)*\\s*<!DOCTYPE(\\s)+html(|(\\s)+[^>]*)>", 2);
    public static final Pattern b = Pattern.compile("^\\uFEFF?\\s*(\\s*<!--([^-]|(?!-->))*-->)*?\\s*<!DOCTYPE[^>]*>", 2);

    public static String a(Vp vp) throws JSONException {
        C2601s7 c2601s7 = AbstractC2773w7.n5;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue() && vp.T) {
            C2881yn c2881yn = vp.V;
            c2881yn.getClass();
            if (((JSONObject) c2881yn.b).optBoolean((String) rVar.c.a(AbstractC2773w7.p5), true) && vp.b != 4) {
                int i = c2881yn.K() == 1 ? 3 : 1;
                String str = vp.l0;
                JSONObject jSONObject = new JSONObject();
                try {
                    jSONObject.put("creativeType", AbstractC1642h.c(i));
                    jSONObject.put("contentUrl", str);
                    return "<script>Object.defineProperty(window,'GOOG_OMID_JAVASCRIPT_SESSION_SERVICE_ENV',{get:function(){return " + jSONObject.toString() + "}});</script>";
                } catch (JSONException e) {
                    com.google.android.gms.ads.internal.util.client.i.i("Unable to build OMID ENV JSON", e);
                }
            }
        }
        return null;
    }

    public static String b(String str, String... strArr) {
        String str2;
        StringBuilder sb = new StringBuilder();
        Matcher matcher = a.matcher(str);
        if (matcher.find()) {
            int iEnd = matcher.end();
            sb.append(str.substring(0, iEnd));
            String str3 = strArr[0];
            if (str3 != null) {
                sb.append(str3);
            }
            sb.append(str.substring(iEnd));
        } else {
            if (!b.matcher(str).find() && (str2 = strArr[0]) != null) {
                sb.append(str2);
            }
            sb.append(str);
        }
        return sb.toString();
    }
}
