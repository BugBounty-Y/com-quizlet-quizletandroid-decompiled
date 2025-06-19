package com.facebook.appevents.ml;

import android.os.Bundle;
import android.text.TextUtils;
import com.comscore.android.id.IdHelperAndroid;
import com.facebook.t;
import com.google.android.gms.internal.mlkit_vision_common.C2;
import java.io.File;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.B;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;
import kotlin.ranges.i;
import kotlin.ranges.l;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class e {
    public static final e a = new e();
    public static final ConcurrentHashMap b = new ConcurrentHashMap();
    public static final List c = B.j("other", "fb_mobile_complete_registration", "fb_mobile_add_to_cart", "fb_mobile_purchase", "fb_mobile_initiated_checkout");
    public static final List d = B.j(IdHelperAndroid.NO_ID_AVAILABLE, "address", "health");

    public static final File d() {
        c task = c.b;
        if (!com.facebook.internal.instrument.crashshield.a.b(e.class)) {
            try {
                Intrinsics.checkNotNullParameter(task, "task");
                d dVar = (d) b.get(task.b());
                if (dVar != null) {
                    return dVar.f;
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(e.class, th);
                return null;
            }
        }
        return null;
    }

    public static final String[] f(c task, float[][] denses, String[] texts) {
        b bVar;
        if (!com.facebook.internal.instrument.crashshield.a.b(e.class)) {
            try {
                Intrinsics.checkNotNullParameter(task, "task");
                Intrinsics.checkNotNullParameter(denses, "denses");
                Intrinsics.checkNotNullParameter(texts, "texts");
                d dVar = (d) b.get(task.b());
                if (dVar != null && (bVar = dVar.g) != null) {
                    float[] fArr = dVar.e;
                    int length = texts.length;
                    int length2 = denses[0].length;
                    a aVar = new a(new int[]{length, length2});
                    for (int i = 0; i < length; i++) {
                        System.arraycopy(denses[i], 0, aVar.c, i * length2, length2);
                    }
                    a aVarA = bVar.a(aVar, texts, task.a());
                    if (aVarA != null && fArr != null && aVarA.c.length != 0 && fArr.length != 0) {
                        int iOrdinal = task.ordinal();
                        e eVar = a;
                        if (iOrdinal == 0) {
                            return eVar.g(aVarA, fArr);
                        }
                        if (iOrdinal == 1) {
                            return eVar.h(aVarA, fArr);
                        }
                        throw new NoWhenBranchMatchedException();
                    }
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(e.class, th);
                return null;
            }
        }
        return null;
    }

    public final void a(JSONObject jSONObject) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            Iterator<String> itKeys = jSONObject.keys();
            while (itKeys.hasNext()) {
                try {
                    d dVarA = C2.a(jSONObject.getJSONObject(itKeys.next()));
                    if (dVarA != null) {
                        b.put(dVarA.a, dVarA);
                    }
                } catch (JSONException unused) {
                    return;
                }
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:24:0x0080 A[Catch: all -> 0x008d, TryCatch #2 {all -> 0x008d, blocks: (B:5:0x0008, B:6:0x001b, B:8:0x0021, B:10:0x0040, B:12:0x0050, B:24:0x0080, B:23:0x007c, B:27:0x008f, B:29:0x009b, B:31:0x00ab, B:34:0x00bd, B:36:0x00c3, B:15:0x0057, B:19:0x0069), top: B:42:0x0008, inners: #1 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b() {
        /*
            r11 = this;
            boolean r0 = com.facebook.internal.instrument.crashshield.a.b(r11)
            if (r0 == 0) goto L8
            goto Lcf
        L8:
            java.util.ArrayList r1 = new java.util.ArrayList     // Catch: java.lang.Throwable -> L8d
            r1.<init>()     // Catch: java.lang.Throwable -> L8d
            java.util.concurrent.ConcurrentHashMap r0 = com.facebook.appevents.ml.e.b     // Catch: java.lang.Throwable -> L8d
            java.util.Set r0 = r0.entrySet()     // Catch: java.lang.Throwable -> L8d
            java.util.Iterator r2 = r0.iterator()     // Catch: java.lang.Throwable -> L8d
            r3 = 0
            r4 = 0
            r7 = r3
            r9 = r4
        L1b:
            boolean r0 = r2.hasNext()     // Catch: java.lang.Throwable -> L8d
            if (r0 == 0) goto Lb9
            java.lang.Object r0 = r2.next()     // Catch: java.lang.Throwable -> L8d
            java.util.Map$Entry r0 = (java.util.Map.Entry) r0     // Catch: java.lang.Throwable -> L8d
            java.lang.Object r5 = r0.getKey()     // Catch: java.lang.Throwable -> L8d
            java.lang.String r5 = (java.lang.String) r5     // Catch: java.lang.Throwable -> L8d
            java.lang.Object r0 = r0.getValue()     // Catch: java.lang.Throwable -> L8d
            r6 = r0
            com.facebook.appevents.ml.d r6 = (com.facebook.appevents.ml.d) r6     // Catch: java.lang.Throwable -> L8d
            com.facebook.appevents.ml.c r0 = com.facebook.appevents.ml.c.b     // Catch: java.lang.Throwable -> L8d
            java.lang.String r0 = r0.b()     // Catch: java.lang.Throwable -> L8d
            boolean r0 = kotlin.jvm.internal.Intrinsics.b(r5, r0)     // Catch: java.lang.Throwable -> L8d
            if (r0 == 0) goto L8f
            java.lang.String r7 = r6.b     // Catch: java.lang.Throwable -> L8d
            int r0 = r6.d     // Catch: java.lang.Throwable -> L8d
            int r9 = java.lang.Math.max(r9, r0)     // Catch: java.lang.Throwable -> L8d
            com.facebook.internal.q r0 = com.facebook.internal.EnumC1562q.SuggestedEvents     // Catch: java.lang.Throwable -> L8d
            boolean r0 = com.facebook.internal.C1563s.b(r0)     // Catch: java.lang.Throwable -> L8d
            if (r0 == 0) goto L8f
            boolean r0 = com.facebook.internal.instrument.crashshield.a.b(r11)     // Catch: java.lang.Throwable -> L8d
            if (r0 == 0) goto L57
            goto L8f
        L57:
            android.content.Context r0 = com.facebook.o.a()     // Catch: java.lang.Exception -> L66 java.lang.Throwable -> L7b
            android.content.res.Resources r0 = r0.getResources()     // Catch: java.lang.Exception -> L66 java.lang.Throwable -> L7b
            android.content.res.Configuration r0 = r0.getConfiguration()     // Catch: java.lang.Exception -> L66 java.lang.Throwable -> L7b
            java.util.Locale r0 = r0.locale     // Catch: java.lang.Exception -> L66 java.lang.Throwable -> L7b
            goto L67
        L66:
            r0 = r3
        L67:
            if (r0 == 0) goto L80
            java.lang.String r0 = r0.getLanguage()     // Catch: java.lang.Throwable -> L7b
            java.lang.String r8 = "locale.language"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r0, r8)     // Catch: java.lang.Throwable -> L7b
            java.lang.String r8 = "en"
            boolean r0 = kotlin.text.StringsKt.G(r0, r8, r4)     // Catch: java.lang.Throwable -> L7b
            if (r0 == 0) goto L8f
            goto L80
        L7b:
            r0 = move-exception
            com.facebook.internal.instrument.crashshield.a.a(r11, r0)     // Catch: java.lang.Throwable -> L8d
            goto L8f
        L80:
            androidx.camera.camera2.internal.h r0 = new androidx.camera.camera2.internal.h     // Catch: java.lang.Throwable -> L8d
            r8 = 14
            r0.<init>(r8)     // Catch: java.lang.Throwable -> L8d
            r6.h = r0     // Catch: java.lang.Throwable -> L8d
            r1.add(r6)     // Catch: java.lang.Throwable -> L8d
            goto L8f
        L8d:
            r0 = move-exception
            goto Ld0
        L8f:
            com.facebook.appevents.ml.c r0 = com.facebook.appevents.ml.c.a     // Catch: java.lang.Throwable -> L8d
            java.lang.String r0 = r0.b()     // Catch: java.lang.Throwable -> L8d
            boolean r0 = kotlin.jvm.internal.Intrinsics.b(r5, r0)     // Catch: java.lang.Throwable -> L8d
            if (r0 == 0) goto L1b
            java.lang.String r7 = r6.b     // Catch: java.lang.Throwable -> L8d
            int r0 = r6.d     // Catch: java.lang.Throwable -> L8d
            int r9 = java.lang.Math.max(r9, r0)     // Catch: java.lang.Throwable -> L8d
            com.facebook.internal.q r0 = com.facebook.internal.EnumC1562q.IntelligentIntegrity     // Catch: java.lang.Throwable -> L8d
            boolean r0 = com.facebook.internal.C1563s.b(r0)     // Catch: java.lang.Throwable -> L8d
            if (r0 == 0) goto L1b
            androidx.camera.camera2.internal.h r0 = new androidx.camera.camera2.internal.h     // Catch: java.lang.Throwable -> L8d
            r5 = 15
            r0.<init>(r5)     // Catch: java.lang.Throwable -> L8d
            r6.h = r0     // Catch: java.lang.Throwable -> L8d
            r1.add(r6)     // Catch: java.lang.Throwable -> L8d
            goto L1b
        Lb9:
            if (r7 == 0) goto Lcf
            if (r9 <= 0) goto Lcf
            boolean r0 = r1.isEmpty()     // Catch: java.lang.Throwable -> L8d
            if (r0 != 0) goto Lcf
            com.facebook.appevents.ml.d r5 = new com.facebook.appevents.ml.d     // Catch: java.lang.Throwable -> L8d
            java.lang.String r6 = "MTML"
            r8 = 0
            r10 = 0
            r5.<init>(r6, r7, r8, r9, r10)     // Catch: java.lang.Throwable -> L8d
            com.google.android.gms.internal.mlkit_vision_common.C2.b(r5, r1)     // Catch: java.lang.Throwable -> L8d
        Lcf:
            return
        Ld0:
            com.facebook.internal.instrument.crashshield.a.a(r11, r0)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.ml.e.b():void");
    }

    public final JSONObject c() {
        if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
            try {
                Bundle bundle = new Bundle();
                bundle.putString("fields", TextUtils.join(",", new String[]{"use_case", "version_id", "asset_uri", "rules_uri", "thresholds"}));
                String str = t.j;
                t tVarQ = assistantMode.utils.studiableMetadata.b.Q(null, "app/model_asset", null);
                Intrinsics.checkNotNullParameter(bundle, "<set-?>");
                tVarQ.d = bundle;
                JSONObject jSONObject = tVarQ.c().b;
                if (jSONObject != null) {
                    return e(jSONObject);
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(this, th);
                return null;
            }
        }
        return null;
    }

    public final JSONObject e(JSONObject jSONObject) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return null;
        }
        try {
            JSONObject jSONObject2 = new JSONObject();
            try {
                JSONArray jSONArray = jSONObject.getJSONArray("data");
                int length = jSONArray.length();
                for (int i = 0; i < length; i++) {
                    JSONObject jSONObject3 = jSONArray.getJSONObject(i);
                    JSONObject jSONObject4 = new JSONObject();
                    jSONObject4.put("version_id", jSONObject3.getString("version_id"));
                    jSONObject4.put("use_case", jSONObject3.getString("use_case"));
                    jSONObject4.put("thresholds", jSONObject3.getJSONArray("thresholds"));
                    jSONObject4.put("asset_uri", jSONObject3.getString("asset_uri"));
                    if (jSONObject3.has("rules_uri")) {
                        jSONObject4.put("rules_uri", jSONObject3.getString("rules_uri"));
                    }
                    jSONObject2.put(jSONObject3.getString("use_case"), jSONObject4);
                }
                return jSONObject2;
            } catch (JSONException unused) {
                return new JSONObject();
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
            return null;
        }
    }

    public final String[] g(a aVar, float[] fArr) {
        if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
            try {
                int[] iArr = aVar.a;
                int i = iArr[0];
                int i2 = iArr[1];
                float[] fArr2 = aVar.c;
                if (i2 == fArr.length) {
                    IntRange intRangeH = l.h(0, i);
                    ArrayList arrayList = new ArrayList(C.q(intRangeH, 10));
                    i it2 = intRangeH.iterator();
                    while (it2.c) {
                        int iNextInt = it2.nextInt();
                        Object obj = IdHelperAndroid.NO_ID_AVAILABLE;
                        int length = fArr.length;
                        int i3 = 0;
                        int i4 = 0;
                        while (i3 < length) {
                            int i5 = i4 + 1;
                            if (fArr2[(iNextInt * i2) + i4] >= fArr[i3]) {
                                obj = d.get(i4);
                            }
                            i3++;
                            i4 = i5;
                        }
                        arrayList.add((String) obj);
                    }
                    return (String[]) arrayList.toArray(new String[0]);
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(this, th);
                return null;
            }
        }
        return null;
    }

    public final String[] h(a aVar, float[] fArr) {
        if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
            try {
                int[] iArr = aVar.a;
                int i = iArr[0];
                int i2 = iArr[1];
                float[] fArr2 = aVar.c;
                if (i2 == fArr.length) {
                    IntRange intRangeH = l.h(0, i);
                    ArrayList arrayList = new ArrayList(C.q(intRangeH, 10));
                    i it2 = intRangeH.iterator();
                    while (it2.c) {
                        int iNextInt = it2.nextInt();
                        Object obj = "other";
                        int length = fArr.length;
                        int i3 = 0;
                        int i4 = 0;
                        while (i3 < length) {
                            int i5 = i4 + 1;
                            if (fArr2[(iNextInt * i2) + i4] >= fArr[i3]) {
                                obj = c.get(i4);
                            }
                            i3++;
                            i4 = i5;
                        }
                        arrayList.add((String) obj);
                    }
                    return (String[]) arrayList.toArray(new String[0]);
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(this, th);
                return null;
            }
        }
        return null;
    }
}
