package androidx.compose.foundation.gestures;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase;
import android.os.SystemClock;
import android.text.TextUtils;
import android.util.Log;
import androidx.datastore.core.InterfaceC1076h;
import com.comscore.streaming.EventType;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.api.ApiException;
import com.google.android.gms.internal.ads.AbstractC1795We;
import com.google.android.gms.internal.ads.AbstractC1972di;
import com.google.android.gms.internal.ads.AbstractC2025es;
import com.google.android.gms.internal.ads.AbstractC2224ja;
import com.google.android.gms.internal.ads.AbstractC2270kd;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.C1923cd;
import com.google.android.gms.internal.ads.C1932cm;
import com.google.android.gms.internal.ads.C1985dw;
import com.google.android.gms.internal.ads.C2227jd;
import com.google.android.gms.internal.ads.C2267ka;
import com.google.android.gms.internal.ads.C2313ld;
import com.google.android.gms.internal.ads.C2601s7;
import com.google.android.gms.internal.ads.C2695uF;
import com.google.android.gms.internal.ads.C2772w6;
import com.google.android.gms.internal.ads.C2815x6;
import com.google.android.gms.internal.ads.C2846xv;
import com.google.android.gms.internal.ads.Ew;
import com.google.android.gms.internal.ads.Fi;
import com.google.android.gms.internal.ads.Gq;
import com.google.android.gms.internal.ads.Hk;
import com.google.android.gms.internal.ads.InterfaceC2122h0;
import com.google.android.gms.internal.ads.InterfaceC2380n0;
import com.google.android.gms.internal.ads.L9;
import com.google.android.gms.internal.ads.LA;
import com.google.android.gms.internal.ads.Pq;
import com.google.android.gms.internal.ads.Qv;
import com.google.android.gms.internal.ads.RunnableC2012ef;
import com.google.android.gms.internal.ads.Uq;
import com.quizlet.db.data.models.persisted.DBStudySet;
import java.io.EOFException;
import java.io.InterruptedIOException;
import java.io.Serializable;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class l1 implements com.google.android.gms.tasks.c, com.google.android.gms.internal.ads.V, com.google.android.gms.internal.ads.W, Gq, io.reactivex.rxjava3.functions.h {
    public final /* synthetic */ int a;
    public long b;
    public Object c;

    public /* synthetic */ l1(long j, Object obj, int i) {
        this.a = i;
        this.b = j;
        this.c = obj;
    }

    public static /* synthetic */ Serializable C(l1 l1Var, String str, kotlin.coroutines.jvm.internal.i iVar, int i) {
        if ((i & 1) != 0) {
            str = null;
        }
        return l1Var.z(str, iVar);
    }

    public static final void J(Hk hk, String str, long j) {
        if (hk != null) {
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Ec)).booleanValue()) {
                Fi fiA = hk.a();
                fiA.o("action", "lat_init");
                fiA.o(str, Long.toString(j));
                fiA.x();
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.io.Serializable A(java.util.ArrayList r14, kotlin.coroutines.jvm.internal.c r15) {
        /*
            r13 = this;
            boolean r0 = r15 instanceof com.quizlet.features.folders.addtofolder.viewmodel.usecase.a
            if (r0 == 0) goto L13
            r0 = r15
            com.quizlet.features.folders.addtofolder.viewmodel.usecase.a r0 = (com.quizlet.features.folders.addtofolder.viewmodel.usecase.a) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.features.folders.addtofolder.viewmodel.usecase.a r0 = new com.quizlet.features.folders.addtofolder.viewmodel.usecase.a
            r0.<init>(r13, r15)
        L18:
            java.lang.Object r15 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 0
            r4 = 1
            if (r2 == 0) goto L38
            if (r2 != r4) goto L30
            java.util.List r14 = r0.k
            androidx.compose.foundation.gestures.l1 r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r15)     // Catch: java.lang.Exception -> L2c
            goto L4f
        L2c:
            r0 = move-exception
            r14 = r0
            goto Lae
        L30:
            java.lang.IllegalStateException r14 = new java.lang.IllegalStateException
            java.lang.String r15 = "call to 'resume' before 'invoke' with coroutine"
            r14.<init>(r15)
            throw r14
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r15)
            java.lang.Object r15 = r13.c     // Catch: java.lang.Exception -> L2c
            com.quizlet.data.interactor.notes.f r15 = (com.quizlet.data.interactor.notes.f) r15     // Catch: java.lang.Exception -> L2c
            r0.j = r13     // Catch: java.lang.Exception -> L2c
            r0.k = r14     // Catch: java.lang.Exception -> L2c
            r0.n = r4     // Catch: java.lang.Exception -> L2c
            r2 = 100
            java.io.Serializable r15 = r15.a(r2, r3, r4, r0)     // Catch: java.lang.Exception -> L2c
            if (r15 != r1) goto L4e
            return r1
        L4e:
            r0 = r13
        L4f:
            java.lang.Iterable r15 = (java.lang.Iterable) r15     // Catch: java.lang.Exception -> L2c
            java.util.ArrayList r1 = new java.util.ArrayList     // Catch: java.lang.Exception -> L2c
            r2 = 10
            int r2 = kotlin.collections.C.q(r15, r2)     // Catch: java.lang.Exception -> L2c
            r1.<init>(r2)     // Catch: java.lang.Exception -> L2c
            java.util.Iterator r15 = r15.iterator()     // Catch: java.lang.Exception -> L2c
        L60:
            boolean r2 = r15.hasNext()     // Catch: java.lang.Exception -> L2c
            if (r2 == 0) goto Lad
            java.lang.Object r2 = r15.next()     // Catch: java.lang.Exception -> L2c
            com.quizlet.data.model.NotesToValueInfo r2 = (com.quizlet.data.model.NotesToValueInfo) r2     // Catch: java.lang.Exception -> L2c
            long r5 = r0.b     // Catch: java.lang.Exception -> L2c
            com.quizlet.ui.models.content.listitem.f r8 = com.google.android.gms.internal.mlkit_vision_barcode.V5.e(r2, r5)     // Catch: java.lang.Exception -> L2c
            com.quizlet.ui.models.content.listitem.i r7 = new com.quizlet.ui.models.content.listitem.i     // Catch: java.lang.Exception -> L2c
            java.lang.String r9 = r8.a     // Catch: java.lang.Exception -> L2c
            long r10 = r2.l     // Catch: java.lang.Exception -> L2c
            r12 = 24
            r7.<init>(r8, r9, r10, r12)     // Catch: java.lang.Exception -> L2c
            if (r14 == 0) goto L87
            boolean r2 = r14.isEmpty()     // Catch: java.lang.Exception -> L2c
            if (r2 == 0) goto L87
        L85:
            r2 = r3
            goto La4
        L87:
            java.util.Iterator r2 = r14.iterator()     // Catch: java.lang.Exception -> L2c
        L8b:
            boolean r5 = r2.hasNext()     // Catch: java.lang.Exception -> L2c
            if (r5 == 0) goto L85
            java.lang.Object r5 = r2.next()     // Catch: java.lang.Exception -> L2c
            com.quizlet.ui.models.content.listitem.o r5 = (com.quizlet.ui.models.content.listitem.o) r5     // Catch: java.lang.Exception -> L2c
            java.lang.String r5 = r5.d()     // Catch: java.lang.Exception -> L2c
            java.lang.String r6 = r8.a     // Catch: java.lang.Exception -> L2c
            boolean r5 = kotlin.jvm.internal.Intrinsics.b(r5, r6)     // Catch: java.lang.Exception -> L2c
            if (r5 == 0) goto L8b
            r2 = r4
        La4:
            com.quizlet.features.folders.addtofolder.data.s r5 = new com.quizlet.features.folders.addtofolder.data.s     // Catch: java.lang.Exception -> L2c
            r5.<init>(r7, r2)     // Catch: java.lang.Exception -> L2c
            r1.add(r5)     // Catch: java.lang.Exception -> L2c
            goto L60
        Lad:
            return r1
        Lae:
            timber.log.a r15 = timber.log.c.a
            java.lang.String r0 = "Failed to load study notes"
            java.lang.Object[] r1 = new java.lang.Object[r3]
            r15.i(r14, r0, r1)
            kotlin.collections.K r14 = kotlin.collections.K.a
            return r14
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.l1.A(java.util.ArrayList, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object B(long r5, kotlin.coroutines.jvm.internal.c r7) {
        /*
            r4 = this;
            boolean r0 = r7 instanceof com.quizlet.features.folders.viewmodel.usecases.a
            if (r0 == 0) goto L13
            r0 = r7
            com.quizlet.features.folders.viewmodel.usecases.a r0 = (com.quizlet.features.folders.viewmodel.usecases.a) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.features.folders.viewmodel.usecases.a r0 = new com.quizlet.features.folders.viewmodel.usecases.a
            r0.<init>(r4, r7)
        L18:
            java.lang.Object r7 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            long r5 = r0.k
            androidx.compose.foundation.gestures.l1 r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L48
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r0.j = r4
            r0.k = r5
            r0.n = r3
            java.lang.Object r7 = r4.c
            com.quizlet.featuregate.features.folder.e r7 = (com.quizlet.featuregate.features.folder.e) r7
            java.lang.Object r7 = r7.a(r0)
            if (r7 != r1) goto L47
            return r1
        L47:
            r0 = r4
        L48:
            java.lang.Boolean r7 = (java.lang.Boolean) r7
            boolean r7 = r7.booleanValue()
            if (r7 == 0) goto L57
            long r0 = r0.b
            int r5 = (r0 > r5 ? 1 : (r0 == r5 ? 0 : -1))
            if (r5 != 0) goto L57
            goto L58
        L57:
            r3 = 0
        L58:
            java.lang.Boolean r5 = java.lang.Boolean.valueOf(r3)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.l1.B(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0014  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object D(java.lang.String r9, com.quizlet.generated.enums.y1 r10, kotlin.coroutines.jvm.internal.c r11) {
        /*
            r8 = this;
            boolean r0 = r11 instanceof com.quizlet.data.interactor.folderstudymaterial.p
            if (r0 == 0) goto L14
            r0 = r11
            com.quizlet.data.interactor.folderstudymaterial.p r0 = (com.quizlet.data.interactor.folderstudymaterial.p) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L14
            int r1 = r1 - r2
            r0.l = r1
        L12:
            r6 = r0
            goto L1a
        L14:
            com.quizlet.data.interactor.folderstudymaterial.p r0 = new com.quizlet.data.interactor.folderstudymaterial.p
            r0.<init>(r8, r11)
            goto L12
        L1a:
            java.lang.Object r11 = r6.j
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r6.l
            r7 = 1
            if (r1 == 0) goto L35
            if (r1 != r7) goto L2d
            androidx.glance.appwidget.protobuf.Z.e(r11)
            kotlin.r r11 = (kotlin.r) r11
            java.lang.Object r9 = r11.a
            goto L58
        L2d:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r10 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r10)
            throw r9
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            java.lang.Long r3 = new java.lang.Long
            long r1 = r8.b
            r3.<init>(r1)
            com.quizlet.data.model.J0 r11 = com.quizlet.data.model.J0.e
            r1 = 11
            r2 = 0
            com.quizlet.data.model.J0 r5 = com.quizlet.data.model.J0.a(r11, r2, r7, r1)
            r6.l = r7
            java.lang.Object r11 = r8.c
            r1 = r11
            com.quizlet.remote.model.folderstudymaterial.m r1 = (com.quizlet.remote.model.folderstudymaterial.m) r1
            r4 = r9
            r2 = r10
            java.lang.Object r9 = r1.b(r2, r3, r4, r5, r6)
            if (r9 != r0) goto L58
            return r0
        L58:
            kotlin.p r10 = kotlin.r.b
            boolean r10 = r9 instanceof kotlin.q
            if (r10 != 0) goto L84
            java.util.List r9 = (java.util.List) r9
            java.util.ArrayList r10 = new java.util.ArrayList
            r10.<init>()
            java.util.Iterator r9 = r9.iterator()
        L69:
            boolean r11 = r9.hasNext()
            if (r11 == 0) goto L7b
            java.lang.Object r11 = r9.next()
            boolean r0 = r11 instanceof com.quizlet.data.model.CreatedFolderStudyMaterial
            if (r0 == 0) goto L69
            r10.add(r11)
            goto L69
        L7b:
            boolean r9 = r10.isEmpty()
            r9 = r9 ^ r7
            java.lang.Boolean r9 = java.lang.Boolean.valueOf(r9)
        L84:
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.l1.D(java.lang.String, com.quizlet.generated.enums.y1, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public okhttp3.r E() {
        com.android.billingclient.api.h hVar = new com.android.billingclient.api.h(3);
        while (true) {
            String line = ((okio.A) this.c).y(this.b);
            this.b -= line.length();
            if (line.length() == 0) {
                return hVar.d();
            }
            Intrinsics.checkNotNullParameter(line, "line");
            int iL = StringsKt.L(line, ':', 1, false, 4);
            if (iL != -1) {
                String strSubstring = line.substring(0, iL);
                Intrinsics.checkNotNullExpressionValue(strSubstring, "this as java.lang.String…ing(startIndex, endIndex)");
                String strSubstring2 = line.substring(iL + 1);
                Intrinsics.checkNotNullExpressionValue(strSubstring2, "this as java.lang.String).substring(startIndex)");
                hVar.b(strSubstring, strSubstring2);
            } else if (line.charAt(0) == ':') {
                String strSubstring3 = line.substring(1);
                Intrinsics.checkNotNullExpressionValue(strSubstring3, "this as java.lang.String).substring(startIndex)");
                hVar.b("", strSubstring3);
            } else {
                hVar.b("", line);
            }
        }
    }

    public boolean F(int i) {
        if (i >= 64) {
            u();
            return ((l1) this.c).F(i - 64);
        }
        long j = 1 << i;
        long j2 = this.b;
        boolean z = (j2 & j) != 0;
        long j3 = j2 & (~j);
        this.b = j3;
        long j4 = j - 1;
        this.b = (j3 & j4) | Long.rotateRight((~j4) & j3, 1);
        l1 l1Var = (l1) this.c;
        if (l1Var != null) {
            if (l1Var.v(0)) {
                H(63);
            }
            ((l1) this.c).F(0);
        }
        return z;
    }

    public void G() {
        this.b = 0L;
        l1 l1Var = (l1) this.c;
        if (l1Var != null) {
            l1Var.G();
        }
    }

    public void H(int i) {
        if (i < 64) {
            this.b |= 1 << i;
        } else {
            u();
            ((l1) this.c).H(i - 64);
        }
    }

    public void I(Context context, VersionInfoParcel versionInfoParcel, boolean z, C1923cd c1923cd, String str, String str2, RunnableC2012ef runnableC2012ef, Uq uq, Hk hk, Long l, boolean z2) throws JSONException {
        Pq pq;
        Exception exc;
        JSONObject jSONObject;
        PackageInfo packageInfoC;
        Uq uq2 = uq;
        int i = 0;
        com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
        jVar.k.getClass();
        if (SystemClock.elapsedRealtime() - this.b < 5000) {
            com.google.android.gms.ads.internal.util.client.i.h("Not retrying to fetch app settings");
            return;
        }
        com.google.android.gms.common.util.b bVar = jVar.k;
        bVar.getClass();
        this.b = SystemClock.elapsedRealtime();
        if (c1923cd != null && !TextUtils.isEmpty(c1923cd.e)) {
            long j = c1923cd.f;
            bVar.getClass();
            if (System.currentTimeMillis() - j <= ((Long) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.k4)).longValue() && c1923cd.h) {
                return;
            }
        }
        if (context == null) {
            com.google.android.gms.ads.internal.util.client.i.h("Context not provided to fetch application settings");
            return;
        }
        if (TextUtils.isEmpty(str) && TextUtils.isEmpty(str2)) {
            com.google.android.gms.ads.internal.util.client.i.h("App settings could not be fetched. Required parameters missing");
            return;
        }
        Context applicationContext = context.getApplicationContext();
        if (applicationContext == null) {
            applicationContext = context;
        }
        this.c = applicationContext;
        Pq pqF = LA.f(context, 4);
        pqF.zzi();
        C2267ka c2267kaD = jVar.r.d((Context) this.c, versionInfoParcel, uq2);
        L9 l9 = AbstractC2224ja.b;
        com.google.android.gms.ads.internal.c cVarA = c2267kaD.a("google.afma.config.fetchAppSettings", l9, l9);
        try {
            jSONObject = new JSONObject();
        } catch (Exception e) {
            e = e;
            pq = pqF;
            exc = e;
            com.google.android.gms.ads.internal.util.client.i.f("Error requesting application settings", exc);
            pq.g(exc);
            pq.h(false);
            uq2.b(pq.l());
        }
        try {
            if (!TextUtils.isEmpty(str)) {
                jSONObject.put("app_id", str);
            } else if (!TextUtils.isEmpty(str2)) {
                jSONObject.put("ad_unit_id", str2);
            }
            jSONObject.put("is_init", z);
            jSONObject.put("pn", context.getPackageName());
            C2601s7 c2601s7 = AbstractC2773w7.a;
            com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
            jSONObject.put("experiment_ids", TextUtils.join(",", rVar.a.h()));
            jSONObject.put("js", versionInfoParcel.a);
            if (((Boolean) rVar.c.a(AbstractC2773w7.z9)).booleanValue()) {
                jSONObject.put("inspector_enabled", z2);
            }
            try {
                ApplicationInfo applicationInfo = ((Context) this.c).getApplicationInfo();
                if (applicationInfo != null && (packageInfoC = com.google.android.gms.common.wrappers.c.a(context).c(applicationInfo.packageName, 0)) != null) {
                    jSONObject.put("version", packageInfoC.versionCode);
                }
            } catch (PackageManager.NameNotFoundException unused) {
                com.google.android.gms.ads.internal.util.A.l("Error fetching PackageInfo.");
            }
            C2313ld c2313ldA = cVarA.a(jSONObject);
            try {
                com.google.android.gms.ads.internal.c cVar = new com.google.android.gms.ads.internal.c(this, l, hk, pqF, uq2);
                pq = pqF;
                uq2 = uq2;
                try {
                    C2227jd c2227jd = AbstractC2270kd.g;
                    C2846xv c2846xvN = AbstractC2025es.N(c2313ldA, cVar, c2227jd);
                    C1985dw c1985dw = c2313ldA.a;
                    if (runnableC2012ef != null) {
                        c1985dw.a(runnableC2012ef, c2227jd);
                    }
                    if (l != null) {
                        c1985dw.a(new com.google.common.util.concurrent.d(this, hk, l), c2227jd);
                    }
                    if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.K7)).booleanValue()) {
                        c2846xvN.a(new Qv(i, c2846xvN, new Ew("ConfigLoader.maybeFetchNewAppSettings", 3)), c2227jd);
                    } else {
                        AbstractC1972di.f(c2846xvN, "ConfigLoader.maybeFetchNewAppSettings");
                    }
                } catch (Exception e2) {
                    e = e2;
                    exc = e;
                    com.google.android.gms.ads.internal.util.client.i.f("Error requesting application settings", exc);
                    pq.g(exc);
                    pq.h(false);
                    uq2.b(pq.l());
                }
            } catch (Exception e3) {
                e = e3;
                pq = pqF;
                uq2 = uq2;
            }
        } catch (Exception e4) {
            exc = e4;
            pq = pqF;
            com.google.android.gms.ads.internal.util.client.i.f("Error requesting application settings", exc);
            pq.g(exc);
            pq.h(false);
            uq2.b(pq.l());
        }
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        switch (this.a) {
            case 20:
                Long teacherId = (Long) obj;
                Intrinsics.checkNotNullParameter(teacherId, "teacherId");
                com.quizlet.infra.legacysyncengine.features.properties.d dVar = (com.quizlet.infra.legacysyncengine.features.properties.d) this.c;
                com.google.firebase.crashlytics.internal.settings.b bVar = dVar.b;
                long jLongValue = teacherId.longValue();
                io.reactivex.rxjava3.core.p stopToken = dVar.f;
                Intrinsics.checkNotNullParameter(stopToken, "stopToken");
                androidx.work.impl.model.v vVar = (androidx.work.impl.model.v) bVar.b;
                Intrinsics.checkNotNullParameter(stopToken, "stopToken");
                io.reactivex.rxjava3.internal.operators.single.g gVarG = ((androidx.work.impl.model.c) vVar.c).c(stopToken, new com.quizlet.data.interactor.classmembership.a(vVar, jLongValue, 0)).g(com.quizlet.infra.legacysyncengine.features.properties.c.n);
                Intrinsics.checkNotNullExpressionValue(gVarG, "map(...)");
                io.reactivex.rxjava3.internal.operators.single.g gVarE = gVarG.e(new com.quizlet.data.interactor.course.c(bVar, this.b, stopToken));
                Intrinsics.checkNotNullExpressionValue(gVarE, "flatMap(...)");
                return new io.reactivex.rxjava3.internal.operators.single.b(gVarE);
            case 21:
            default:
                DBStudySet dBStudySet = (DBStudySet) obj;
                Intrinsics.d(dBStudySet);
                return new com.quizlet.quizletandroid.data.management.a(dBStudySet, (com.quizlet.qutils.data.offline.d) this.c, this.b);
            case EventType.WINDOW_STATE /* 22 */:
                List it2 = (List) obj;
                Intrinsics.checkNotNullParameter(it2, "it");
                io.reactivex.rxjava3.internal.operators.single.g gVarG2 = ((com.quizlet.local.ormlite.models.studysetwithcreator.a) ((com.quizlet.data.repository.activitycenter.b) this.c).c).c(kotlin.collections.A.b(Long.valueOf(this.b))).g(new com.quizlet.data.interactor.folderwithcreatorinclass.a(it2));
                Intrinsics.checkNotNullExpressionValue(gVarG2, "map(...)");
                return gVarG2;
        }
    }

    @Override // com.google.android.gms.internal.ads.Gq
    public Object b(Object obj) throws SQLException {
        SQLiteDatabase sQLiteDatabase = (SQLiteDatabase) obj;
        if (((com.google.android.gms.ads.internal.util.C) ((C1932cm) this.c).b).k()) {
            return null;
        }
        C2772w6 c2772w6L = C2815x6.L();
        c2772w6L.e();
        C2815x6 c2815x6 = (C2815x6) c2772w6L.b;
        long j = this.b;
        C2815x6.H(c2815x6, j);
        byte[] bArrD = ((C2815x6) c2772w6L.c()).d();
        sQLiteDatabase.execSQL("UPDATE offline_signal_statistics SET value = value+1 WHERE statistic_name = 'total_requests'");
        LA.w(sQLiteDatabase, j, bArrD);
        return null;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2779wD
    public int d(int i, byte[] bArr, int i2) {
        return ((com.google.android.gms.internal.ads.P) this.c).d(i, bArr, i2);
    }

    @Override // com.google.android.gms.internal.ads.V
    public void e(int i) throws EOFException, InterruptedIOException {
        ((com.google.android.gms.internal.ads.P) this.c).n(i, false);
    }

    @Override // com.google.android.gms.internal.ads.V
    public long f() {
        return ((com.google.android.gms.internal.ads.P) this.c).d - this.b;
    }

    @Override // com.google.android.gms.internal.ads.V
    public void g(int i) throws EOFException, InterruptedIOException {
        ((com.google.android.gms.internal.ads.P) this.c).p(i);
    }

    @Override // com.google.android.gms.internal.ads.V
    public boolean h(byte[] bArr, int i, int i2, boolean z) {
        return ((com.google.android.gms.internal.ads.P) this.c).h(bArr, 0, i2, z);
    }

    @Override // com.google.android.gms.internal.ads.V
    public void i() {
        ((com.google.android.gms.internal.ads.P) this.c).f = 0;
    }

    @Override // com.google.android.gms.internal.ads.V
    public long j() {
        return ((com.google.android.gms.internal.ads.P) this.c).c - this.b;
    }

    @Override // com.google.android.gms.internal.ads.V
    public boolean k(byte[] bArr, int i, int i2, boolean z) {
        return ((com.google.android.gms.internal.ads.P) this.c).k(bArr, 0, i2, z);
    }

    @Override // com.google.android.gms.internal.ads.V
    public void l(int i, byte[] bArr, int i2) {
        ((com.google.android.gms.internal.ads.P) this.c).k(bArr, i, i2, false);
    }

    @Override // com.google.android.gms.internal.ads.W
    public void n() {
        ((C2695uF) this.c).n();
    }

    @Override // com.google.android.gms.internal.ads.V
    public void o(int i, byte[] bArr, int i2) throws EOFException, InterruptedIOException {
        ((com.google.android.gms.internal.ads.P) this.c).h(bArr, i, i2, false);
    }

    @Override // com.google.android.gms.internal.ads.W
    public void p(InterfaceC2122h0 interfaceC2122h0) {
        ((C2695uF) this.c).p(new com.google.android.gms.internal.ads.L0(this, interfaceC2122h0, interfaceC2122h0));
    }

    @Override // com.google.android.gms.internal.ads.W
    public InterfaceC2380n0 q(int i, int i2) {
        return ((C2695uF) this.c).q(i, i2);
    }

    public void r(int i) {
        if (i < 64) {
            this.b &= ~(1 << i);
            return;
        }
        l1 l1Var = (l1) this.c;
        if (l1Var != null) {
            l1Var.r(i - 64);
        }
    }

    public int s(int i) {
        l1 l1Var = (l1) this.c;
        if (l1Var == null) {
            return i >= 64 ? Long.bitCount(this.b) : Long.bitCount(this.b & ((1 << i) - 1));
        }
        if (i < 64) {
            return Long.bitCount(this.b & ((1 << i) - 1));
        }
        return Long.bitCount(this.b) + l1Var.s(i - 64);
    }

    @Override // com.google.android.gms.tasks.c
    public void t(Exception exc) {
        ConnectionResult connectionResult;
        switch (this.a) {
            case 3:
                Log.i("AdvertisingIdClient", "getting error as ".concat(String.valueOf(exc.getMessage())));
                if ((exc instanceof ApiException) && (connectionResult = ((ApiException) exc).a.d) != null && connectionResult.b == 24) {
                    ((com.google.android.gms.ads.identifier.d) this.c).b.set(this.b);
                    break;
                }
                break;
            case 10:
                ((AtomicLong) ((com.quizlet.data.interactor.school.b) this.c).c).set(this.b);
                break;
            case 11:
                ((AtomicLong) ((com.quizlet.data.repository.activitycenter.b) this.c).c).set(this.b);
                break;
            case 12:
                ((AtomicLong) ((com.quizlet.data.repository.searchexplanations.c) this.c).c).set(this.b);
                break;
            default:
                ((AtomicLong) ((io.ktor.client.plugins.api.d) this.c).d).set(this.b);
                break;
        }
    }

    public String toString() {
        switch (this.a) {
            case 1:
                if (((l1) this.c) == null) {
                    return Long.toBinaryString(this.b);
                }
                return ((l1) this.c).toString() + "xx" + Long.toBinaryString(this.b);
            default:
                return super.toString();
        }
    }

    public void u() {
        if (((l1) this.c) == null) {
            this.c = new l1(1);
        }
    }

    public boolean v(int i) {
        if (i < 64) {
            return (this.b & (1 << i)) != 0;
        }
        u();
        return ((l1) this.c).v(i - 64);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object w(kotlin.coroutines.jvm.internal.c r6) {
        /*
            r5 = this;
            boolean r0 = r6 instanceof com.quizlet.local.datastore.preferences.C4577m
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.local.datastore.preferences.m r0 = (com.quizlet.local.datastore.preferences.C4577m) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.local.datastore.preferences.m r0 = new com.quizlet.local.datastore.preferences.m
            r0.<init>(r5, r6)
        L18:
            java.lang.Object r6 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L49
        L27:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            java.lang.Object r6 = r5.c
            androidx.datastore.core.h r6 = (androidx.datastore.core.InterfaceC1076h) r6
            kotlinx.coroutines.flow.i r6 = r6.getData()
            androidx.compose.material3.internal.H r2 = new androidx.compose.material3.internal.H
            r4 = 6
            r2.<init>(r4, r6, r5)
            r0.l = r3
            java.lang.Object r6 = kotlinx.coroutines.flow.e0.r(r2, r0)
            if (r6 != r1) goto L49
            return r1
        L49:
            java.lang.Boolean r6 = (java.lang.Boolean) r6
            if (r6 == 0) goto L52
            boolean r6 = r6.booleanValue()
            goto L53
        L52:
            r6 = 0
        L53:
            java.lang.Boolean r6 = java.lang.Boolean.valueOf(r6)
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.l1.w(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object x(long r11, kotlin.coroutines.jvm.internal.c r13) {
        /*
            r10 = this;
            boolean r0 = r13 instanceof com.quizlet.local.datastore.preferences.C4581q
            if (r0 == 0) goto L13
            r0 = r13
            com.quizlet.local.datastore.preferences.q r0 = (com.quizlet.local.datastore.preferences.C4581q) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.local.datastore.preferences.q r0 = new com.quizlet.local.datastore.preferences.q
            r0.<init>(r10, r13)
        L18:
            java.lang.Object r13 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto L4b
        L27:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r12 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r12)
            throw r11
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            java.lang.Object r13 = r10.c
            androidx.datastore.core.h r13 = (androidx.datastore.core.InterfaceC1076h) r13
            kotlinx.coroutines.flow.i r5 = r13.getData()
            com.quizlet.local.datastore.preferences.p r4 = new com.quizlet.local.datastore.preferences.p
            r9 = 0
            r6 = r10
            r7 = r11
            r4.<init>(r5, r6, r7, r9)
            r0.l = r3
            java.lang.Object r13 = kotlinx.coroutines.flow.e0.r(r4, r0)
            if (r13 != r1) goto L4b
            return r1
        L4b:
            java.lang.Boolean r13 = (java.lang.Boolean) r13
            if (r13 == 0) goto L54
            boolean r11 = r13.booleanValue()
            goto L55
        L54:
            r11 = 0
        L55:
            java.lang.Boolean r11 = java.lang.Boolean.valueOf(r11)
            return r11
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.l1.x(long, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public void y(int i, boolean z) {
        if (i >= 64) {
            u();
            ((l1) this.c).y(i - 64, z);
            return;
        }
        long j = this.b;
        boolean z2 = (Long.MIN_VALUE & j) != 0;
        long j2 = (1 << i) - 1;
        this.b = ((j & (~j2)) << 1) | (j & j2);
        if (z) {
            H(i);
        } else {
            r(i);
        }
        if (z2 || ((l1) this.c) != null) {
            u();
            ((l1) this.c).y(0, z2);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r0v3, types: [java.lang.Iterable, java.lang.Object] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.io.Serializable z(java.lang.String r12, kotlin.coroutines.jvm.internal.c r13) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 238
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.foundation.gestures.l1.z(java.lang.String, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    @Override // com.google.android.gms.internal.ads.V
    public long zze() {
        return ((com.google.android.gms.internal.ads.P) this.c).zze() - this.b;
    }

    public l1(com.google.android.gms.internal.ads.P p, long j) {
        this.a = 6;
        this.c = p;
        AbstractC1795We.B(p.d >= j);
        this.b = j;
    }

    public /* synthetic */ l1(Object obj, long j, int i) {
        this.a = i;
        this.c = obj;
        this.b = j;
    }

    public l1(com.google.android.gms.common.util.b bVar) {
        this.a = 14;
        com.google.android.gms.common.internal.u.h(bVar);
        this.c = bVar;
    }

    public l1(long j, com.quizlet.featuregate.features.folder.e folderEligibility) {
        this.a = 18;
        Intrinsics.checkNotNullParameter(folderEligibility, "folderEligibility");
        this.b = j;
        this.c = folderEligibility;
    }

    public l1(com.quizlet.remote.model.folderstudymaterial.m folderStudyMaterialsRepository, long j) {
        this.a = 15;
        Intrinsics.checkNotNullParameter(folderStudyMaterialsRepository, "folderStudyMaterialsRepository");
        this.c = folderStudyMaterialsRepository;
        this.b = j;
    }

    public l1(com.google.firebase.crashlytics.internal.settings.b getFlashcardSetsUseCase, long j) {
        this.a = 19;
        Intrinsics.checkNotNullParameter(getFlashcardSetsUseCase, "getFlashcardSetsUseCase");
        this.c = getFlashcardSetsUseCase;
        this.b = j;
    }

    public l1(com.quizlet.data.interactor.notes.f getAllStudyNotesUseCase, long j) {
        this.a = 16;
        Intrinsics.checkNotNullParameter(getAllStudyNotesUseCase, "getAllStudyNotesUseCase");
        this.c = getAllStudyNotesUseCase;
        this.b = j;
    }

    public l1(com.quizlet.quizletandroid.interactor.m getAllStudySetsCardWithCreatorUseCase, long j) {
        this.a = 17;
        Intrinsics.checkNotNullParameter(getAllStudySetsCardWithCreatorUseCase, "getAllStudySetsCardWithCreatorUseCase");
        this.c = getAllStudySetsCardWithCreatorUseCase;
        this.b = j;
    }

    public l1(okio.A source) {
        this.a = 24;
        Intrinsics.checkNotNullParameter(source, "source");
        this.c = source;
        this.b = 262144L;
    }

    public l1(InterfaceC1076h dataStore, long j) {
        this.a = 21;
        Intrinsics.checkNotNullParameter(dataStore, "dataStore");
        this.c = dataStore;
        this.b = j;
    }

    public l1(com.fasterxml.uuid.c cVar) {
        SecureRandom secureRandom;
        this.a = 2;
        byte[] bArr = new byte[16];
        char[] cArr = com.fasterxml.uuid.a.c;
        synchronized (com.fasterxml.uuid.a.class) {
            try {
                if (com.fasterxml.uuid.a.d == null) {
                    com.fasterxml.uuid.a.d = new SecureRandom();
                }
                secureRandom = com.fasterxml.uuid.a.d;
            } catch (Throwable th) {
                throw th;
            }
        }
        byte[] bArr2 = new byte[6];
        synchronized (secureRandom) {
            secureRandom.nextBytes(bArr2);
        }
        bArr2[0] = (byte) (bArr2[0] | 1);
        long j = new com.fasterxml.uuid.a(bArr2).a;
        int i = (int) (j >> 32);
        bArr[10] = (byte) (i >> 8);
        bArr[11] = (byte) i;
        int i2 = (int) j;
        bArr[12] = (byte) (i2 >> 24);
        bArr[13] = (byte) (i2 >> 16);
        bArr[14] = (byte) (i2 >> 8);
        bArr[15] = (byte) i2;
        int i3 = cVar.c & 65535;
        bArr[8] = (byte) (i3 >> 8);
        bArr[9] = (byte) i3;
        this.b = ((((com.fasterxml.uuid.impl.a.a(8, bArr) << 32) | ((com.fasterxml.uuid.impl.a.a(12, bArr) << 32) >>> 32)) << 2) >>> 2) | Long.MIN_VALUE;
        this.c = cVar;
    }

    public l1(int i) {
        this.a = i;
        switch (i) {
            case 4:
                break;
            case 8:
                this.c = new ArrayList();
                break;
            default:
                this.b = 0L;
                break;
        }
    }

    public l1(EnumC0320d0 enumC0320d0) {
        this.a = 0;
        this.c = enumC0320d0;
        this.b = 0L;
    }
}
