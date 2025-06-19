package com.google.android.gms.internal.ads;

import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Color;
import android.graphics.drawable.BitmapDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.text.TextUtils;
import com.amazon.device.ads.DTBMetricsConfiguration;
import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import java.util.ArrayList;
import java.util.Collections;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class Gj {
    public Object a;
    public Object b;
    public Object c;
    public Object d;
    public Object e;
    public Object f;
    public Object g;
    public Object h;
    public Object i;
    public Object j;
    public Object k;
    public Object l;
    public Object m;
    public Object n;
    public Object o;
    public Object p;
    public Object q;
    public Object r = "";

    public static androidx.compose.runtime.internal.j a(androidx.compose.runtime.internal.j jVar, String str) {
        androidx.compose.runtime.internal.j jVar2 = new androidx.compose.runtime.internal.j();
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) jVar.b)) {
            jVar2.b = (String) jVar.b;
        }
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) jVar.i)) {
            jVar2.i = (String) jVar.i;
        }
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) jVar.c)) {
            jVar2.c = (String) jVar.c;
        }
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) jVar.d)) {
            jVar2.d = (String) jVar.d;
        }
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) jVar.f)) {
            jVar2.f = (String) jVar.f;
        }
        jVar2.g = com.onetrust.otpublishers.headless.Internal.a.j((String) jVar.g) ? "0" : (String) jVar.g;
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) jVar.e)) {
            str = (String) jVar.e;
        }
        if (!com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            jVar2.e = str;
        }
        jVar2.a = com.onetrust.otpublishers.headless.Internal.a.j((String) jVar.a) ? "#2D6B6767" : (String) jVar.a;
        jVar2.h = com.onetrust.otpublishers.headless.Internal.a.j((String) jVar.h) ? "20" : (String) jVar.h;
        jVar2.j = (androidx.navigation.internal.m) jVar.j;
        return jVar2;
    }

    public static androidx.navigation.internal.m c(JSONObject jSONObject, androidx.navigation.internal.m mVar, String str, boolean z) {
        androidx.navigation.internal.m mVar2 = new androidx.navigation.internal.m();
        com.google.android.gms.cloudmessaging.k kVar = (com.google.android.gms.cloudmessaging.k) mVar.d;
        mVar2.d = kVar;
        mVar2.b = d(jSONObject, (String) mVar.b, "PcTextColor");
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) kVar.d)) {
            ((com.google.android.gms.cloudmessaging.k) mVar2.d).d = (String) kVar.d;
        }
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) mVar.f)) {
            mVar2.f = (String) mVar.f;
        }
        if (!z) {
            String strOptString = (String) mVar.g;
            if (com.onetrust.otpublishers.headless.Internal.a.j(strOptString) || strOptString == null) {
                strOptString = !com.onetrust.otpublishers.headless.Internal.a.j(str) ? jSONObject.optString(str) : "";
            }
            mVar2.g = strOptString;
        }
        return mVar2;
    }

    public static String d(JSONObject jSONObject, String str, String str2) {
        if (!com.onetrust.otpublishers.headless.Internal.a.j(str) && str != null) {
            return str;
        }
        try {
            return jSONObject.getString(str2);
        } catch (JSONException e) {
            com.google.android.gms.measurement.internal.Z.p("error while applying header text color", e, "VLDataConfig", 6);
            return "";
        }
    }

    public static Integer i(String str, JSONObject jSONObject) {
        try {
            JSONObject jSONObject2 = jSONObject.getJSONObject(str);
            return Integer.valueOf(Color.rgb(jSONObject2.getInt("r"), jSONObject2.getInt("g"), jSONObject2.getInt("b")));
        } catch (JSONException unused) {
            return null;
        }
    }

    public static final com.google.android.gms.ads.internal.client.E0 j(JSONObject jSONObject) {
        if (jSONObject == null) {
            return null;
        }
        String strOptString = jSONObject.optString("reason");
        String strOptString2 = jSONObject.optString("ping_url");
        if (TextUtils.isEmpty(strOptString) || TextUtils.isEmpty(strOptString2)) {
            return null;
        }
        return new com.google.android.gms.ads.internal.client.E0(strOptString, strOptString2);
    }

    public androidx.constraintlayout.motion.widget.n b(androidx.constraintlayout.motion.widget.n nVar) {
        androidx.constraintlayout.motion.widget.n nVar2 = new androidx.constraintlayout.motion.widget.n();
        com.google.android.gms.cloudmessaging.k kVar = (com.google.android.gms.cloudmessaging.k) nVar.d;
        nVar2.d = kVar;
        String strOptString = (String) nVar.j;
        JSONObject jSONObject = (JSONObject) this.a;
        if (com.onetrust.otpublishers.headless.Internal.a.j(strOptString) || strOptString == null) {
            strOptString = !com.onetrust.otpublishers.headless.Internal.a.j("PreferenceCenterConfirmText") ? jSONObject.optString("PreferenceCenterConfirmText") : "";
        }
        nVar2.j = strOptString;
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) kVar.d)) {
            ((com.google.android.gms.cloudmessaging.k) nVar2.d).d = (String) kVar.d;
        }
        nVar2.f = d((JSONObject) this.a, (String) nVar.f, "PcButtonTextColor");
        nVar2.e = d((JSONObject) this.a, (String) nVar.e, "PcButtonColor");
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.g)) {
            nVar2.g = (String) nVar.g;
        }
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.i)) {
            nVar2.i = (String) nVar.i;
        }
        if (!com.onetrust.otpublishers.headless.Internal.a.j((String) nVar.h)) {
            nVar2.h = (String) nVar.h;
        }
        return nVar2;
    }

    public void e() {
        io.ktor.client.plugins.api.d dVar = ((com.onetrust.otpublishers.headless.UI.UIProperty.g) this.b).t;
        if (((JSONObject) this.a).has("PCenterVendorListFilterAria")) {
            dVar.b = ((JSONObject) this.a).optString("PCenterVendorListFilterAria");
        }
        if (((JSONObject) this.a).has("PCVendorListFilterUnselectedAriaLabel")) {
            dVar.d = ((JSONObject) this.a).optString("PCVendorListFilterUnselectedAriaLabel");
        }
        if (((JSONObject) this.a).has("PCVendorListFilterSelectedAriaLabel")) {
            dVar.c = ((JSONObject) this.a).optString("PCVendorListFilterSelectedAriaLabel");
        }
        if (((JSONObject) this.a).has("PCenterVendorListSearch")) {
            ((com.onetrust.otpublishers.headless.UI.UIProperty.g) this.b).n.i = ((JSONObject) this.a).optString("PCenterVendorListSearch");
        }
    }

    public com.google.common.util.concurrent.e f(int i, JSONObject jSONObject, boolean z) {
        if (jSONObject == null) {
            return Tv.b;
        }
        final String strOptString = jSONObject.optString(DTBMetricsConfiguration.APSMETRICS_URL);
        if (TextUtils.isEmpty(strOptString)) {
            return Tv.b;
        }
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.o2)).booleanValue() && i != 0) {
            Bundle bundle = ((Ek) this.r).d;
            com.google.android.gms.ads.internal.j.C.k.getClass();
            bundle.putLong(AbstractC1642h.b(i), System.currentTimeMillis());
        }
        final double dOptDouble = jSONObject.optDouble("scale", 1.0d);
        final boolean zOptBoolean = jSONObject.optBoolean("is_transparent", true);
        final int iOptInt = jSONObject.optInt(OTUXParamsKeys.OT_UX_WIDTH, -1);
        final int iOptInt2 = jSONObject.optInt(OTUXParamsKeys.OT_UX_HEIGHT, -1);
        if (z) {
            return AbstractC2025es.E(new BinderC2474p8(null, Uri.parse(strOptString), dOptDouble, iOptInt, iOptInt2));
        }
        final C2920zj c2920zj = (C2920zj) this.b;
        c2920zj.a.getClass();
        C2313ld c2313ld = new C2313ld();
        com.google.android.gms.ads.internal.util.q.a.e(new com.google.android.gms.ads.internal.util.p(strOptString, c2313ld));
        C2889yv c2889yvL = AbstractC2025es.L(AbstractC2025es.L(c2313ld, new InterfaceC2544qt() { // from class: com.google.android.gms.internal.ads.yj
            @Override // com.google.android.gms.internal.ads.InterfaceC2544qt
            public final Object apply(Object obj) {
                byte[] bArr = ((A3) obj).b;
                BitmapFactory.Options options = new BitmapFactory.Options();
                options.inDensity = (int) (dOptDouble * 160.0d);
                if (!zOptBoolean) {
                    options.inPreferredConfig = Bitmap.Config.RGB_565;
                }
                C2601s7 c2601s7 = AbstractC2773w7.d6;
                com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                boolean zBooleanValue = ((Boolean) rVar.c.a(c2601s7)).booleanValue();
                C2920zj c2920zj2 = c2920zj;
                if (zBooleanValue) {
                    options.inJustDecodeBounds = true;
                    c2920zj2.a(bArr, options);
                    options.inJustDecodeBounds = false;
                    int i2 = options.outWidth * options.outHeight;
                    if (i2 > 0) {
                        options.inSampleSize = 1 << ((33 - Integer.numberOfLeadingZeros((i2 - 1) / ((Integer) rVar.c.a(AbstractC2773w7.e6)).intValue())) / 2);
                    }
                }
                return c2920zj2.a(bArr, options);
            }
        }, c2920zj.c), new InterfaceC2544qt() { // from class: com.google.android.gms.internal.ads.Dj
            @Override // com.google.android.gms.internal.ads.InterfaceC2544qt
            public final Object apply(Object obj) {
                return new BinderC2474p8(new BitmapDrawable(Resources.getSystem(), (Bitmap) obj), Uri.parse(strOptString), dOptDouble, iOptInt, iOptInt2);
            }
        }, (Xv) this.g);
        return jSONObject.optBoolean("require") ? AbstractC2025es.N(c2889yvL, new D9(c2889yvL, 5), AbstractC2270kd.g) : AbstractC2025es.A(c2889yvL, Exception.class, new C2487pf(1), AbstractC2270kd.g);
    }

    public com.google.common.util.concurrent.e g(JSONArray jSONArray, boolean z, boolean z2, int i) {
        if (jSONArray == null || jSONArray.length() <= 0) {
            return AbstractC2025es.E(Collections.EMPTY_LIST);
        }
        ArrayList arrayList = new ArrayList();
        int length = z2 ? jSONArray.length() : 1;
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.o2)).booleanValue()) {
            AbstractC1642h.t(com.google.android.gms.ads.internal.j.C.k, ((Ek) this.r).d, AbstractC1642h.b(i));
        }
        for (int i2 = 0; i2 < length; i2++) {
            arrayList.add(f(0, jSONArray.optJSONObject(i2), z));
        }
        return AbstractC2025es.L(new Gv(AbstractC2330lu.n(arrayList), true), new C2853y1(7), (Xv) this.g);
    }

    /* JADX WARN: Removed duplicated region for block: B:11:0x004e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.google.android.gms.internal.ads.C2846xv h(org.json.JSONObject r12, com.google.android.gms.internal.ads.Vp r13, com.google.android.gms.internal.ads.Xp r14, com.google.android.gms.ads.internal.a r15, com.google.android.gms.internal.ads.C1673Cc r16) {
        /*
            r11 = this;
            java.lang.String r0 = "base_url"
            java.lang.String r8 = r12.optString(r0)
            java.lang.String r0 = "html"
            java.lang.String r9 = r12.optString(r0)
            java.lang.String r0 = "width"
            r1 = 0
            int r0 = r12.optInt(r0, r1)
            java.lang.String r2 = "height"
            int r12 = r12.optInt(r2, r1)
            if (r0 != 0) goto L24
            if (r12 == 0) goto L1e
            goto L25
        L1e:
            com.google.android.gms.ads.internal.client.zzr r12 = com.google.android.gms.ads.internal.client.zzr.b()
            r3 = r12
            goto L34
        L24:
            r1 = r0
        L25:
            com.google.android.gms.ads.internal.client.zzr r0 = new com.google.android.gms.ads.internal.client.zzr
            com.google.android.gms.ads.h r2 = new com.google.android.gms.ads.h
            r2.<init>(r1, r12)
            java.lang.Object r12 = r11.a
            android.content.Context r12 = (android.content.Context) r12
            r0.<init>(r12, r2)
            r3 = r0
        L34:
            java.lang.Object r12 = r11.i
            r2 = r12
            com.google.android.gms.internal.ads.Oj r2 = (com.google.android.gms.internal.ads.Oj) r2
            r2.getClass()
            com.google.android.gms.internal.ads.s7 r12 = com.google.android.gms.internal.ads.AbstractC2773w7.o2
            com.google.android.gms.ads.internal.client.r r0 = com.google.android.gms.ads.internal.client.r.d
            com.google.android.gms.internal.ads.u7 r0 = r0.c
            java.lang.Object r12 = r0.a(r12)
            java.lang.Boolean r12 = (java.lang.Boolean) r12
            boolean r12 = r12.booleanValue()
            if (r12 == 0) goto L5b
            com.google.android.gms.internal.ads.Ek r12 = r2.i
            android.os.Bundle r12 = r12.d
            com.google.android.gms.ads.internal.j r0 = com.google.android.gms.ads.internal.j.C
            com.google.android.gms.common.util.b r0 = r0.k
            java.lang.String r1 = "native-assets-loading-video-composition-start"
            com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h.t(r0, r12, r1)
        L5b:
            com.google.android.gms.internal.ads.Tv r12 = com.google.android.gms.internal.ads.Tv.b
            com.google.android.gms.internal.ads.Fj r1 = new com.google.android.gms.internal.ads.Fj
            r10 = 1
            r4 = r13
            r5 = r14
            r6 = r15
            r7 = r16
            r1.<init>(r2, r3, r4, r5, r6, r7, r8, r9, r10)
            java.util.concurrent.Executor r13 = r2.b
            com.google.android.gms.internal.ads.xv r12 = com.google.android.gms.internal.ads.AbstractC2025es.N(r12, r1, r13)
            com.google.android.gms.internal.ads.Cj r13 = new com.google.android.gms.internal.ads.Cj
            r14 = 1
            r13.<init>(r12, r14)
            com.google.android.gms.internal.ads.jd r14 = com.google.android.gms.internal.ads.AbstractC2270kd.g
            com.google.android.gms.internal.ads.xv r12 = com.google.android.gms.internal.ads.AbstractC2025es.N(r12, r13, r14)
            return r12
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.Gj.h(org.json.JSONObject, com.google.android.gms.internal.ads.Vp, com.google.android.gms.internal.ads.Xp, com.google.android.gms.ads.internal.a, com.google.android.gms.internal.ads.Cc):com.google.android.gms.internal.ads.xv");
    }
}
