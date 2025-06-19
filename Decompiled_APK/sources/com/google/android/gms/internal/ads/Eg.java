package com.google.android.gms.internal.ads;

import android.content.Context;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import java.util.concurrent.atomic.AtomicBoolean;

/* loaded from: classes2.dex */
public final class Eg implements Jh, InterfaceC2618si {
    public com.quizlet.data.repository.studysetwithcreatorinclass.g a;
    public final Context c;
    public final Uq d;
    public final VersionInfoParcel e;
    public final Xv f;
    public boolean g = false;
    public boolean h = false;
    public final AtomicBoolean b = new AtomicBoolean();

    public Eg(Context context, Uq uq, VersionInfoParcel versionInfoParcel, Xv xv) {
        this.c = context;
        this.d = uq;
        this.e = versionInfoParcel;
        this.f = xv;
    }

    @Override // com.google.android.gms.internal.ads.Jh
    public final void J0(C1849aq c1849aq) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2618si
    public final void a(String str) {
        c();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2618si
    public final void b(com.google.android.gms.ads.nonagon.signalgeneration.q qVar) {
        c();
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x003a  */
    /* JADX WARN: Removed duplicated region for block: B:22:0x006e  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x007e  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void c() {
        /*
            r5 = this;
            java.util.concurrent.atomic.AtomicBoolean r0 = r5.b
            r1 = 1
            boolean r0 = r0.getAndSet(r1)
            if (r0 == 0) goto Lb
            goto L9d
        Lb:
            com.google.android.gms.internal.ads.I3 r0 = com.google.android.gms.internal.ads.W7.j
            java.lang.Object r0 = r0.o()
            java.lang.Boolean r0 = (java.lang.Boolean) r0
            boolean r0 = r0.booleanValue()
            r2 = 2
            if (r0 == 0) goto L1c
        L1a:
            r3 = r2
            goto L66
        L1c:
            com.google.android.gms.internal.ads.I3 r0 = com.google.android.gms.internal.ads.W7.k
            java.lang.Object r0 = r0.o()
            java.lang.Boolean r0 = (java.lang.Boolean) r0
            boolean r0 = r0.booleanValue()
            r3 = 3
            if (r0 == 0) goto L2c
            goto L66
        L2c:
            com.google.android.gms.internal.ads.I3 r0 = com.google.android.gms.internal.ads.W7.i
            java.lang.Object r0 = r0.o()
            java.lang.Boolean r0 = (java.lang.Boolean) r0
            boolean r0 = r0.booleanValue()
            if (r0 != 0) goto L3c
        L3a:
            r3 = r1
            goto L66
        L3c:
            com.google.android.gms.ads.internal.j r0 = com.google.android.gms.ads.internal.j.C
            com.google.android.gms.internal.ads.ed r0 = r0.h
            com.google.android.gms.ads.internal.util.C r0 = r0.d()
            com.google.android.gms.internal.ads.cd r0 = r0.n()
            java.lang.String r0 = r0.e
            org.json.JSONObject r4 = new org.json.JSONObject     // Catch: org.json.JSONException -> L3a
            r4.<init>(r0)     // Catch: org.json.JSONException -> L3a
            java.lang.String r0 = "local_flag_write"
            java.lang.String r0 = r4.optString(r0)     // Catch: org.json.JSONException -> L3a
            java.lang.String r4 = "client"
            boolean r4 = android.text.TextUtils.equals(r0, r4)     // Catch: org.json.JSONException -> L3a
            if (r4 == 0) goto L5e
            goto L1a
        L5e:
            java.lang.String r4 = "service"
            boolean r0 = android.text.TextUtils.equals(r0, r4)     // Catch: org.json.JSONException -> L3a
            if (r0 == 0) goto L3a
        L66:
            int r3 = r3 + (-1)
            com.google.android.gms.internal.ads.Uq r0 = r5.d
            android.content.Context r4 = r5.c
            if (r3 == r1) goto L7e
            if (r3 == r2) goto L71
            goto L9d
        L71:
            com.google.android.gms.ads.internal.j r2 = com.google.android.gms.ads.internal.j.C
            com.quizlet.data.repository.studysetwithcreator.d r2 = r2.r
            com.google.android.gms.ads.internal.util.client.VersionInfoParcel r3 = com.google.android.gms.ads.internal.util.client.VersionInfoParcel.a()
            com.google.android.gms.internal.ads.ka r0 = r2.e(r4, r3, r0)
            goto L8a
        L7e:
            com.google.android.gms.ads.internal.j r2 = com.google.android.gms.ads.internal.j.C
            com.quizlet.data.repository.studysetwithcreator.d r2 = r2.r
            com.google.android.gms.ads.internal.util.client.VersionInfoParcel r3 = com.google.android.gms.ads.internal.util.client.VersionInfoParcel.a()
            com.google.android.gms.internal.ads.ka r0 = r2.d(r4, r3, r0)
        L8a:
            java.lang.String r2 = "google.afma.sdkConstants.getSdkConstants"
            com.google.android.gms.internal.ads.L9 r3 = com.google.android.gms.internal.ads.AbstractC2224ja.b
            com.google.android.gms.ads.internal.c r0 = r0.a(r2, r3, r3)
            com.quizlet.data.repository.studysetwithcreatorinclass.g r2 = new com.quizlet.data.repository.studysetwithcreatorinclass.g
            com.google.android.gms.ads.internal.util.client.VersionInfoParcel r3 = r5.e
            r2.<init>(r4, r0, r3)
            r5.a = r2
            r5.g = r1
        L9d:
            boolean r0 = r5.g
            if (r0 != 0) goto La2
            goto Lcd
        La2:
            com.quizlet.data.repository.studysetwithcreatorinclass.g r0 = r5.a
            if (r0 == 0) goto Lcd
            com.google.common.util.concurrent.e r0 = r0.y()
            boolean r1 = r5.h
            if (r1 != 0) goto Lc8
            com.google.android.gms.internal.ads.I3 r1 = com.google.android.gms.internal.ads.Q7.i
            java.lang.Object r1 = r1.o()
            java.lang.Boolean r1 = (java.lang.Boolean) r1
            boolean r1 = r1.booleanValue()
            if (r1 == 0) goto Lc8
            com.google.android.gms.internal.ads.e r1 = new com.google.android.gms.internal.ads.e
            r2 = 26
            r1.<init>(r5, r2)
            com.google.android.gms.internal.ads.Xv r2 = r5.f
            r0.a(r1, r2)
        Lc8:
            java.lang.String r1 = "persistFlagsClient"
            com.google.android.gms.internal.ads.AbstractC1972di.f(r0, r1)
        Lcd:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.Eg.c():void");
    }

    @Override // com.google.android.gms.internal.ads.Jh
    public final void r0(zzbvl zzbvlVar) {
        c();
    }
}
