package com.google.android.gms.internal.ads;

import android.app.Application;
import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.text.TextUtils;
import com.google.android.gms.ads.internal.client.C1614q;
import com.google.android.gms.internal.measurement.C2977d;
import com.google.android.gms.internal.measurement.C2987f;
import com.google.android.gms.internal.measurement.C3056t;
import com.google.android.gms.internal.measurement.C3083y1;
import com.google.android.gms.internal.measurement.InterfaceC3027n;
import java.io.File;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Objects;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.Kc, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1721Kc implements Pv {
    public static C1721Kc f;
    public final /* synthetic */ int a;
    public Object b;
    public Object c;
    public Object d;
    public Object e;

    public /* synthetic */ C1721Kc() {
        this.a = 2;
    }

    private final void h(Throwable th) {
    }

    public static synchronized C1721Kc i(Context context) {
        try {
            C1721Kc c1721Kc = f;
            if (c1721Kc != null) {
                return c1721Kc;
            }
            Context applicationContext = context.getApplicationContext();
            AbstractC2773w7.a(applicationContext);
            com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
            com.google.android.gms.ads.internal.util.C cD = jVar.h.d();
            cD.p(applicationContext);
            applicationContext.getClass();
            com.google.android.gms.common.util.b bVar = jVar.k;
            bVar.getClass();
            C1739Nc c1739Nc = jVar.y;
            AbstractC1981ds.w(C1739Nc.class, c1739Nc);
            C1721Kc c1721Kc2 = new C1721Kc(applicationContext, bVar, cD, c1739Nc);
            f = c1721Kc2;
            SharedPreferencesOnSharedPreferenceChangeListenerC1685Ec sharedPreferencesOnSharedPreferenceChangeListenerC1685Ec = (SharedPreferencesOnSharedPreferenceChangeListenerC1685Ec) ((BC) c1721Kc2.c).zzb();
            SharedPreferences sharedPreferences = sharedPreferencesOnSharedPreferenceChangeListenerC1685Ec.b;
            sharedPreferences.registerOnSharedPreferenceChangeListener(sharedPreferencesOnSharedPreferenceChangeListenerC1685Ec);
            sharedPreferencesOnSharedPreferenceChangeListenerC1685Ec.onSharedPreferenceChanged(sharedPreferences, "gad_has_consent_for_cookies");
            C2601s7 c2601s7 = AbstractC2773w7.G0;
            com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
            if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
                sharedPreferencesOnSharedPreferenceChangeListenerC1685Ec.onSharedPreferenceChanged(sharedPreferences, "IABTCF_TCString");
            } else {
                sharedPreferencesOnSharedPreferenceChangeListenerC1685Ec.onSharedPreferenceChanged(sharedPreferences, "IABTCF_PurposeConsents");
            }
            C1757Qc c1757Qc = (C1757Qc) ((BC) f.e).zzb();
            if (((Boolean) rVar.c.a(AbstractC2773w7.z0)).booleanValue()) {
                HashMap mapJ = com.google.android.gms.ads.internal.util.F.J((String) rVar.c.a(AbstractC2773w7.A0));
                Iterator it2 = mapJ.keySet().iterator();
                while (it2.hasNext()) {
                    c1757Qc.a((String) it2.next());
                }
                C1745Oc c1745Oc = new C1745Oc(c1757Qc, mapJ);
                synchronized (c1757Qc) {
                    c1757Qc.b.add(c1745Oc);
                }
            }
            return f;
        } catch (Throwable th) {
            throw th;
        }
    }

    public Bitmap a(String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        HashMap map = (HashMap) this.e;
        Bitmap bitmap = (Bitmap) map.get(name);
        if (bitmap != null) {
            return bitmap;
        }
        String str = (String) this.c;
        if (str == null) {
            return null;
        }
        File file = new File(str + '/' + name + ".png");
        if (!file.exists()) {
            return null;
        }
        Bitmap bitmapDecodeFile = BitmapFactory.decodeFile(file.getAbsolutePath());
        map.put(name, bitmapDecodeFile);
        return bitmapDecodeFile;
    }

    public boolean b() {
        Application context = (Application) this.b;
        try {
            String str = com.perimeterx.mobile_sdk.configurations.i.a;
            Intrinsics.checkNotNullParameter(context, "context");
            File file = new File(context.getCacheDir().getAbsolutePath() + "/px/doctor_app_2.0.zip");
            Intrinsics.checkNotNullParameter(context, "context");
            String str2 = context.getCacheDir().getAbsolutePath() + "/px/doctor_app/2.0";
            com.google.android.gms.internal.mlkit_vision_document_scanner.E4.f(file, str2);
            this.c = str2;
            return true;
        } catch (Exception unused) {
            return false;
        }
    }

    @Override // com.google.android.gms.internal.ads.Pv
    /* renamed from: c */
    public void mo15c(Object obj) {
        C2830xf c2830xf;
        switch (this.a) {
            case 3:
                ((C2830xf) this.e).e.a(new C((C2584rr) this.b, (String) obj, (com.google.android.gms.auth.api.signin.internal.h) this.d, 6));
                break;
            default:
                String str = (String) obj;
                InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) this.b;
                Vp vpE = interfaceC2529qe.e();
                if (vpE != null && !vpE.i0) {
                    com.google.android.gms.auth.api.signin.internal.h hVar = vpE.x0;
                    if (!((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.aa)).booleanValue() || (c2830xf = (C2830xf) this.c) == null || !C2830xf.b(str)) {
                        ((C2584rr) this.d).a(str, hVar, null, null);
                        break;
                    } else {
                        C2584rr c2584rr = (C2584rr) this.d;
                        Random random = C1614q.f.e;
                        if (!TextUtils.isEmpty(str)) {
                            com.google.common.util.concurrent.e eVarO = AbstractC2025es.O(c2830xf.c(str, c2830xf.d.a, random), ((Integer) r1.c.a(AbstractC2773w7.na)).intValue(), TimeUnit.MILLISECONDS, c2830xf.g);
                            eVarO.a(new Qv(0, eVarO, new C1721Kc(c2830xf, c2584rr, str, hVar)), c2830xf.e);
                            break;
                        }
                    }
                } else {
                    Xp xpI0 = interfaceC2529qe.i0();
                    if (xpI0 != null) {
                        com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
                        jVar.k.getClass();
                        long jCurrentTimeMillis = System.currentTimeMillis();
                        boolean zA = jVar.h.a(interfaceC2529qe.getContext());
                        boolean z = false;
                        boolean z2 = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.i6)).booleanValue() && vpE != null && vpE.S;
                        if (vpE != null && vpE.d0 != null) {
                            z = true;
                        }
                        com.android.volley.toolbox.d dVar = new com.android.volley.toolbox.d((zA || z2 || z) ? 2 : 1, jCurrentTimeMillis, xpI0.b, str);
                        C2107gm c2107gm = (C2107gm) this.e;
                        c2107gm.getClass();
                        c2107gm.d(new C1732Mb(26, c2107gm, dVar));
                        break;
                    } else {
                        com.google.android.gms.ads.internal.j.C.h.h("BufferingGmsgHandlers.getBufferingClickGmsgHandler", new IllegalArgumentException("Common configuration cannot be null"));
                        break;
                    }
                }
                break;
        }
    }

    public JSONObject d() throws JSONException {
        try {
            String eventName = (String) this.b;
            if (eventName == null) {
                return null;
            }
            String eventCategory = (String) this.e;
            JSONObject eventProperties = new com.google.android.gms.auth.api.signin.internal.h(new com.amazon.aps.shared.metrics.model.d(new com.amazon.aps.shared.metrics.model.b(new com.amazon.aps.shared.metrics.model.a((JSONObject) this.d, eventName, (String) this.c)))).A();
            Intrinsics.checkNotNullParameter(eventCategory, "eventCategory");
            Intrinsics.checkNotNullParameter(eventName, "eventName");
            Intrinsics.checkNotNullParameter(eventProperties, "eventProperties");
            JSONObject jSONObject = new JSONObject();
            JSONObject jSONObject2 = new JSONObject();
            jSONObject2.put("eventSource", "aps_android_sdk");
            jSONObject2.put("eventTime", System.currentTimeMillis());
            jSONObject2.put("eventName", eventName);
            jSONObject2.put("eventCategory", eventCategory);
            jSONObject2.put("eventProperties", eventProperties);
            Unit unit = Unit.a;
            jSONObject.put("Data", jSONObject2);
            jSONObject.put("PartitionKey", System.currentTimeMillis());
            return jSONObject;
        } catch (RuntimeException e) {
            com.amazon.aps.shared.a.e(1, 1, "Error builing the custom metrics object from builder", e);
            return null;
        }
    }

    public void e() {
        com.google.android.gms.internal.mlkit_vision_barcode.S.d();
        androidx.work.impl.model.v vVar = (androidx.work.impl.model.v) this.c;
        vVar.getClass();
        com.google.android.gms.internal.mlkit_vision_barcode.S.d();
        androidx.camera.core.imagecapture.a aVar = (androidx.camera.core.imagecapture.a) vVar.c;
        Objects.requireNonNull(aVar);
        androidx.camera.core.a0 a0Var = (androidx.camera.core.a0) vVar.b;
        Objects.requireNonNull(a0Var);
        androidx.camera.core.a0 a0Var2 = null;
        androidx.camera.core.g0 g0Var = aVar.a;
        Objects.requireNonNull(g0Var);
        g0Var.a();
        androidx.camera.core.g0 g0Var2 = aVar.a;
        Objects.requireNonNull(g0Var2);
        androidx.camera.core.impl.utils.futures.i.d(g0Var2.e).a(new androidx.camera.camera2.internal.r0(a0Var, 1), com.google.android.gms.internal.mlkit_vision_barcode.T.e());
        androidx.camera.core.g0 g0Var3 = aVar.b;
        if (g0Var3 != null) {
            g0Var3.a();
            androidx.camera.core.impl.utils.futures.i.d(aVar.b.e).a(new androidx.camera.camera2.internal.r0(a0Var2, 2), com.google.android.gms.internal.mlkit_vision_barcode.T.e());
        }
        ((C3083y1) this.d).getClass();
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object f(java.lang.String r7, java.lang.String r8, kotlin.coroutines.jvm.internal.c r9) throws java.lang.Throwable {
        /*
            r6 = this;
            boolean r0 = r9 instanceof com.quizlet.login.common.interactors.q
            if (r0 == 0) goto L13
            r0 = r9
            com.quizlet.login.common.interactors.q r0 = (com.quizlet.login.common.interactors.q) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.login.common.interactors.q r0 = new com.quizlet.login.common.interactors.q
            r0.<init>(r6, r9)
        L18:
            java.lang.Object r9 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            r5 = 0
            if (r2 == 0) goto L3b
            if (r2 == r4) goto L33
            if (r2 != r3) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r9)
            return r9
        L2b:
            java.lang.IllegalStateException r7 = new java.lang.IllegalStateException
            java.lang.String r8 = "call to 'resume' before 'invoke' with coroutine"
            r7.<init>(r8)
            throw r7
        L33:
            java.lang.String r7 = r0.k
            com.google.android.gms.internal.ads.Kc r8 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L55
        L3b:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            com.quizlet.login.common.interactors.r r9 = new com.quizlet.login.common.interactors.r
            r9.<init>(r7, r8, r6, r5)
            r0.j = r6
            r0.k = r7
            r0.n = r4
            java.lang.Object r8 = r6.e
            kotlinx.coroutines.y r8 = (kotlinx.coroutines.AbstractC5040y) r8
            java.lang.Object r9 = kotlinx.coroutines.E.J(r8, r9, r0)
            if (r9 != r1) goto L54
            goto L6e
        L54:
            r8 = r6
        L55:
            java.lang.String r2 = "withContext(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r9, r2)
            com.quizlet.login.authentication.data.i r9 = (com.quizlet.login.authentication.data.i) r9
            java.lang.Object r8 = r8.d
            androidx.compose.runtime.internal.j r8 = (androidx.compose.runtime.internal.j) r8
            r0.j = r5
            r0.k = r5
            r0.n = r3
            java.lang.String r2 = "email"
            java.lang.Object r7 = r8.s(r9, r2, r7, r0)
            if (r7 != r1) goto L6f
        L6e:
            return r1
        L6f:
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C1721Kc.f(java.lang.String, java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public C1721Kc g() {
        return new C1721Kc(this, (C3056t) this.c);
    }

    public InterfaceC3027n j(InterfaceC3027n interfaceC3027n) {
        return ((C3056t) this.c).a(this, interfaceC3027n);
    }

    public InterfaceC3027n k(C2977d c2977d) {
        InterfaceC3027n interfaceC3027nA = InterfaceC3027n.Q0;
        Iterator itN = c2977d.n();
        while (itN.hasNext()) {
            interfaceC3027nA = ((C3056t) this.c).a(this, c2977d.i(((Integer) itN.next()).intValue()));
            if (interfaceC3027nA instanceof C2987f) {
                break;
            }
        }
        return interfaceC3027nA;
    }

    public InterfaceC3027n l(String str) {
        HashMap map = (HashMap) this.d;
        if (map.containsKey(str)) {
            return (InterfaceC3027n) map.get(str);
        }
        C1721Kc c1721Kc = (C1721Kc) this.b;
        if (c1721Kc != null) {
            return c1721Kc.l(str);
        }
        throw new IllegalArgumentException(android.support.v4.media.session.a.k(str, " is not defined"));
    }

    public void m(String str, InterfaceC3027n interfaceC3027n) {
        if (((HashMap) this.e).containsKey(str)) {
            return;
        }
        HashMap map = (HashMap) this.d;
        if (interfaceC3027n == null) {
            map.remove(str);
        } else {
            map.put(str, interfaceC3027n);
        }
    }

    public void n(String str, InterfaceC3027n interfaceC3027n) {
        C1721Kc c1721Kc;
        HashMap map = (HashMap) this.d;
        if (!map.containsKey(str) && (c1721Kc = (C1721Kc) this.b) != null && c1721Kc.o(str)) {
            c1721Kc.n(str, interfaceC3027n);
        } else {
            if (((HashMap) this.e).containsKey(str)) {
                return;
            }
            if (interfaceC3027n == null) {
                map.remove(str);
            } else {
                map.put(str, interfaceC3027n);
            }
        }
    }

    public boolean o(String str) {
        if (((HashMap) this.d).containsKey(str)) {
            return true;
        }
        C1721Kc c1721Kc = (C1721Kc) this.b;
        if (c1721Kc != null) {
            return c1721Kc.o(str);
        }
        return false;
    }

    @Override // com.google.android.gms.internal.ads.Pv
    public void zza(Throwable th) {
        switch (this.a) {
            case 3:
                ((C2830xf) this.e).e.a(new RunnableC1788Vd(this, th, (C2584rr) this.b, (String) this.c, (com.google.android.gms.auth.api.signin.internal.h) this.d));
                break;
        }
    }

    public C1721Kc(Context context, com.google.android.gms.common.util.b bVar, com.google.android.gms.ads.internal.util.C c, C1739Nc c1739Nc) {
        this.a = 0;
        this.b = bVar;
        DC dcA = DC.a(context);
        DC dcA2 = DC.a(c);
        int i = 0;
        this.c = BC.b(new C1691Fc(dcA, dcA2, i));
        DC dcA3 = DC.a(bVar);
        BC bcB = BC.b(new C1703Hc(dcA3, dcA2, DC.a(c1739Nc), i));
        this.d = bcB;
        this.e = BC.b(new C1691Fc(dcA, new C1715Jc(dcA3, bcB), 1));
    }

    public C1721Kc(InterfaceC2529qe interfaceC2529qe, C2830xf c2830xf, C2584rr c2584rr, C2107gm c2107gm) {
        this.a = 4;
        this.b = interfaceC2529qe;
        this.c = c2830xf;
        this.d = c2584rr;
        this.e = c2107gm;
    }

    public C1721Kc(C2830xf c2830xf, C2584rr c2584rr, String str, com.google.android.gms.auth.api.signin.internal.h hVar) {
        this.a = 3;
        this.b = c2584rr;
        this.c = str;
        this.d = hVar;
        this.e = c2830xf;
    }

    public C1721Kc(Application context) {
        this.a = 6;
        Intrinsics.checkNotNullParameter(context, "context");
        this.d = new com.perimeterx.mobile_sdk.api_data.d();
        this.e = new HashMap();
        this.b = context;
    }

    public C1721Kc(C1721Kc c1721Kc, C3056t c3056t) {
        this.a = 5;
        this.d = new HashMap();
        this.e = new HashMap();
        this.b = c1721Kc;
        this.c = c3056t;
    }

    public C1721Kc(io.ktor.client.plugins.api.d loginApiClientManager, com.quizlet.qutils.string.c state, androidx.compose.runtime.internal.j handleLoginResponseUseCase, AbstractC5040y ioDispatcher) {
        this.a = 7;
        Intrinsics.checkNotNullParameter(loginApiClientManager, "loginApiClientManager");
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(handleLoginResponseUseCase, "handleLoginResponseUseCase");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.b = loginApiClientManager;
        this.c = state;
        this.d = handleLoginResponseUseCase;
        this.e = ioDispatcher;
    }

    public C1721Kc(androidx.work.impl.model.c dataSource, com.quizlet.quizletandroid.ui.activitycenter.models.a mapper, com.quizlet.quizletandroid.ui.common.ads.prebid.creators.a textbookMapper, com.quizlet.quizletandroid.managers.upgrade.a questionMapper, com.quizlet.quizletandroid.ui.common.adapter.c textbookExerciseMapper) {
        this.a = 8;
        Intrinsics.checkNotNullParameter(dataSource, "dataSource");
        Intrinsics.checkNotNullParameter(mapper, "mapper");
        Intrinsics.checkNotNullParameter(textbookMapper, "textbookMapper");
        Intrinsics.checkNotNullParameter(questionMapper, "questionMapper");
        Intrinsics.checkNotNullParameter(textbookExerciseMapper, "textbookExerciseMapper");
        this.b = dataSource;
        this.c = textbookMapper;
        this.d = questionMapper;
        this.e = textbookExerciseMapper;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:16:0x0077  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x0156  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public C1721Kc(androidx.camera.core.impl.N r17, android.util.Size r18, boolean r19) {
        /*
            Method dump skipped, instructions count: 380
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C1721Kc.<init>(androidx.camera.core.impl.N, android.util.Size, boolean):void");
    }
}
