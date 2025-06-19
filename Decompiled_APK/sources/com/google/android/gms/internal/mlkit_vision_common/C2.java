package com.google.android.gms.internal.mlkit_vision_common;

import android.content.Context;
import android.content.Intent;
import androidx.camera.camera2.internal.C0132i;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.features.settings.SettingsActivity;
import java.io.File;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public abstract class C2 {
    public static com.facebook.appevents.ml.d a(JSONObject jSONObject) throws JSONException {
        float[] fArr;
        float[] fArr2;
        if (jSONObject == null) {
            return null;
        }
        try {
            String useCase = jSONObject.getString("use_case");
            String assetUri = jSONObject.getString("asset_uri");
            String strOptString = jSONObject.optString("rules_uri", null);
            int i = jSONObject.getInt("version_id");
            com.facebook.appevents.ml.e eVar = com.facebook.appevents.ml.e.a;
            JSONArray jSONArray = jSONObject.getJSONArray("thresholds");
            if (com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.ml.e.class)) {
                fArr2 = null;
            } else {
                try {
                    if (com.facebook.internal.instrument.crashshield.a.b(eVar) || jSONArray == null) {
                        fArr = null;
                        fArr2 = fArr;
                    } else {
                        try {
                            fArr = new float[jSONArray.length()];
                            int length = jSONArray.length();
                            for (int i2 = 0; i2 < length; i2++) {
                                try {
                                    String string = jSONArray.getString(i2);
                                    Intrinsics.checkNotNullExpressionValue(string, "jsonArray.getString(i)");
                                    fArr[i2] = Float.parseFloat(string);
                                } catch (JSONException unused) {
                                }
                            }
                        } catch (Throwable th) {
                            com.facebook.internal.instrument.crashshield.a.a(eVar, th);
                        }
                        fArr2 = fArr;
                    }
                } catch (Throwable th2) {
                    com.facebook.internal.instrument.crashshield.a.a(com.facebook.appevents.ml.e.class, th2);
                }
            }
            Intrinsics.checkNotNullExpressionValue(useCase, "useCase");
            Intrinsics.checkNotNullExpressionValue(assetUri, "assetUri");
            return new com.facebook.appevents.ml.d(useCase, assetUri, strOptString, i, fArr2);
        } catch (Exception unused2) {
            return null;
        }
    }

    public static void b(com.facebook.appevents.ml.d master, ArrayList slaves) {
        File[] fileArrListFiles;
        Intrinsics.checkNotNullParameter(master, "master");
        Intrinsics.checkNotNullParameter(slaves, "slaves");
        String str = master.a;
        File fileB = com.facebook.appevents.ml.g.b();
        int i = master.d;
        if (fileB != null && (fileArrListFiles = fileB.listFiles()) != null && fileArrListFiles.length != 0) {
            String str2 = str + '_' + i;
            for (File file : fileArrListFiles) {
                String name = file.getName();
                Intrinsics.checkNotNullExpressionValue(name, "name");
                if (kotlin.text.D.r(name, str, false) && !kotlin.text.D.r(name, str2, false)) {
                    file.delete();
                }
            }
        }
        String str3 = master.a + '_' + i;
        C0132i c0132i = new C0132i(slaves, 24);
        String str4 = master.b;
        File file2 = new File(com.facebook.appevents.ml.g.b(), str3);
        if (str4 == null || file2.exists()) {
            c0132i.c(file2);
        } else {
            new com.facebook.appevents.internal.l(str4, file2, c0132i).execute(new String[0]);
        }
    }

    public static Intent c(Context context) {
        return AbstractC4178x.b(context, "context", context, SettingsActivity.class);
    }
}
