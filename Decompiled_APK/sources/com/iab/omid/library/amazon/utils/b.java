package com.iab.omid.library.amazon.utils;

import android.content.res.Resources;
import android.graphics.Point;
import android.util.Log;
import android.view.WindowManager;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import com.skydoves.balloon.internals.DefinitionKt;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public abstract class b {
    public static WindowManager a;
    public static final String[] b = {"x", "y", OTUXParamsKeys.OT_UX_WIDTH, OTUXParamsKeys.OT_UX_HEIGHT};
    public static float c = Resources.getSystem().getDisplayMetrics().density;

    public static JSONObject a(int i, int i2, int i3, int i4) throws JSONException {
        JSONObject jSONObject = new JSONObject();
        try {
            jSONObject.put("x", i / c);
            jSONObject.put("y", i2 / c);
            jSONObject.put(OTUXParamsKeys.OT_UX_WIDTH, i3 / c);
            jSONObject.put(OTUXParamsKeys.OT_UX_HEIGHT, i4 / c);
            return jSONObject;
        } catch (JSONException e) {
            Log.e("OMIDLIB", "Error with creating viewStateObject", e);
            return jSONObject;
        }
    }

    public static void b(JSONObject jSONObject, String str, Object obj) throws JSONException {
        try {
            jSONObject.put(str, obj);
        } catch (NullPointerException | JSONException e) {
            Log.e("OMIDLIB", "JSONException during JSONObject.put for name [" + str + "]", e);
        }
    }

    public static void c(JSONObject jSONObject, JSONObject jSONObject2) throws JSONException {
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

    /* JADX WARN: Removed duplicated region for block: B:45:0x00b5  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x00d0  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x00e5 A[EDGE_INSN: B:63:0x00e5->B:65:0x00ea BREAK  A[LOOP:1: B:59:0x00d1->B:64:0x00e7]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static boolean e(org.json.JSONObject r8, org.json.JSONObject r9) {
        /*
            Method dump skipped, instructions count: 239
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.iab.omid.library.amazon.utils.b.e(org.json.JSONObject, org.json.JSONObject):boolean");
    }
}
