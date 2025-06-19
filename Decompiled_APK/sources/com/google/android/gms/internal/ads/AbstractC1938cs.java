package com.google.android.gms.internal.ads;

import android.content.res.Resources;
import android.graphics.Point;
import android.view.WindowManager;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.skydoves.balloon.internals.DefinitionKt;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.cs, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC1938cs {
    public static WindowManager a;
    public static final String[] b = {"x", "y", OTUXParamsKeys.OT_UX_WIDTH, OTUXParamsKeys.OT_UX_HEIGHT};
    public static float c = Resources.getSystem().getDisplayMetrics().density;

    public static JSONObject a(int i, int i2, int i3, int i4) {
        JSONObject jSONObject = new JSONObject();
        try {
            jSONObject.put("x", i / c);
            jSONObject.put("y", i2 / c);
            jSONObject.put(OTUXParamsKeys.OT_UX_WIDTH, i3 / c);
            jSONObject.put(OTUXParamsKeys.OT_UX_HEIGHT, i4 / c);
            return jSONObject;
        } catch (JSONException e) {
            LA.l("Error with creating viewStateObject", e);
            return jSONObject;
        }
    }

    public static void b(JSONObject jSONObject, JSONObject jSONObject2) throws JSONException {
        try {
            JSONArray jSONArrayOptJSONArray = jSONObject.optJSONArray("childViews");
            if (jSONArrayOptJSONArray == null) {
                jSONArrayOptJSONArray = new JSONArray();
                jSONObject.put("childViews", jSONArrayOptJSONArray);
            }
            jSONArrayOptJSONArray.put(jSONObject2);
        } catch (JSONException e) {
            e.printStackTrace();
        }
    }

    public static void c(JSONObject jSONObject, String str, Object obj) {
        try {
            jSONObject.put(str, obj);
        } catch (NullPointerException | JSONException e) {
            LA.l("JSONException during JSONObject.put for name [" + str + "]", e);
        }
    }

    public static void d(JSONObject jSONObject) throws JSONException {
        float f;
        float f2;
        if (a != null) {
            Point point = new Point(0, 0);
            a.getDefaultDisplay().getRealSize(point);
            float f3 = point.x;
            float f4 = c;
            f = f3 / f4;
            f2 = point.y / f4;
        } else {
            f = DefinitionKt.NO_Float_VALUE;
            f2 = 0.0f;
        }
        try {
            jSONObject.put(OTUXParamsKeys.OT_UX_WIDTH, f);
            jSONObject.put(OTUXParamsKeys.OT_UX_HEIGHT, f2);
        } catch (JSONException e) {
            e.printStackTrace();
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:51:0x00c8  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static boolean e(org.json.JSONObject r8, org.json.JSONObject r9) {
        /*
            if (r8 != 0) goto L4
            if (r9 == 0) goto Ld9
        L4:
            r0 = 0
            if (r8 == 0) goto Ldb
            if (r9 != 0) goto Lb
            goto Ldb
        Lb:
            java.lang.String[] r1 = com.google.android.gms.internal.ads.AbstractC1938cs.b
            r2 = r0
        Le:
            r3 = 4
            if (r2 >= r3) goto L24
            r3 = r1[r2]
            double r4 = r8.optDouble(r3)
            double r6 = r9.optDouble(r3)
            int r3 = (r4 > r6 ? 1 : (r4 == r6 ? 0 : -1))
            if (r3 == 0) goto L21
            goto Ldb
        L21:
            int r2 = r2 + 1
            goto Le
        L24:
            java.lang.String r1 = "adSessionId"
            java.lang.String r2 = ""
            java.lang.String r3 = r8.optString(r1, r2)
            java.lang.String r1 = r9.optString(r1, r2)
            boolean r1 = r3.equals(r1)
            if (r1 == 0) goto Ldb
            java.lang.String r1 = "noOutputDevice"
            boolean r3 = r8.optBoolean(r1)
            java.lang.Boolean r3 = java.lang.Boolean.valueOf(r3)
            boolean r1 = r9.optBoolean(r1)
            java.lang.Boolean r1 = java.lang.Boolean.valueOf(r1)
            boolean r1 = r3.equals(r1)
            if (r1 == 0) goto Ldb
            java.lang.String r1 = "hasWindowFocus"
            boolean r3 = r8.optBoolean(r1)
            java.lang.Boolean r3 = java.lang.Boolean.valueOf(r3)
            boolean r1 = r9.optBoolean(r1)
            java.lang.Boolean r1 = java.lang.Boolean.valueOf(r1)
            boolean r1 = r3.equals(r1)
            if (r1 == 0) goto Ldb
            java.lang.String r1 = "isFriendlyObstructionFor"
            org.json.JSONArray r3 = r8.optJSONArray(r1)
            org.json.JSONArray r1 = r9.optJSONArray(r1)
            if (r3 != 0) goto L75
            if (r1 != 0) goto L75
            goto La0
        L75:
            if (r3 != 0) goto L79
            if (r1 == 0) goto L88
        L79:
            if (r3 == 0) goto Ldb
            if (r1 != 0) goto L7e
            goto Ldb
        L7e:
            int r4 = r3.length()
            int r5 = r1.length()
            if (r4 != r5) goto Ldb
        L88:
            r4 = r0
        L89:
            int r5 = r3.length()
            if (r4 >= r5) goto La0
            java.lang.String r5 = r3.optString(r4, r2)
            java.lang.String r6 = r1.optString(r4, r2)
            boolean r5 = r5.equals(r6)
            if (r5 == 0) goto Ldb
            int r4 = r4 + 1
            goto L89
        La0:
            java.lang.String r1 = "childViews"
            org.json.JSONArray r8 = r8.optJSONArray(r1)
            org.json.JSONArray r9 = r9.optJSONArray(r1)
            if (r8 != 0) goto Lae
            if (r9 == 0) goto Ld9
        Lae:
            if (r8 != 0) goto Lb2
            if (r9 == 0) goto Lc1
        Lb2:
            if (r8 == 0) goto Ldb
            if (r9 != 0) goto Lb7
            goto Ldb
        Lb7:
            int r1 = r8.length()
            int r2 = r9.length()
            if (r1 != r2) goto Ldb
        Lc1:
            r1 = r0
        Lc2:
            int r2 = r8.length()
            if (r1 >= r2) goto Ld9
            org.json.JSONObject r2 = r8.optJSONObject(r1)
            org.json.JSONObject r3 = r9.optJSONObject(r1)
            boolean r2 = e(r2, r3)
            if (r2 == 0) goto Ldb
            int r1 = r1 + 1
            goto Lc2
        Ld9:
            r8 = 1
            return r8
        Ldb:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.AbstractC1938cs.e(org.json.JSONObject, org.json.JSONObject):boolean");
    }
}
