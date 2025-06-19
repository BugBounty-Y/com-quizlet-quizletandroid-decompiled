package com.google.firebase.perf.logging;

import android.graphics.drawable.Drawable;
import android.media.CamcorderProfile;
import android.os.Bundle;
import android.util.Log;
import androidx.camera.camera2.internal.InterfaceC0127d;
import androidx.camera.camera2.internal.c0;
import androidx.cardview.widget.CardView;
import androidx.fragment.app.AbstractC1136h0;
import com.android.installreferrer.api.InstallReferrerClient;
import com.bumptech.glide.load.engine.u;
import com.bumptech.glide.manager.m;
import com.facebook.B;
import com.facebook.appevents.internal.j;
import com.facebook.appevents.q;
import com.facebook.o;
import com.google.android.gms.ads.mediation.customevent.c;
import com.google.android.gms.internal.measurement.C2991f3;
import com.google.android.gms.internal.measurement.O2;
import com.google.android.gms.internal.measurement.Q2;
import com.google.android.gms.internal.measurement.W3;
import com.google.android.gms.internal.measurement.Y3;
import com.google.android.gms.internal.measurement.Z2;
import com.google.android.gms.internal.measurement.b4;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3559x2;
import com.google.android.gms.measurement.internal.AbstractC3893t;
import com.google.android.gms.measurement.internal.r;
import com.google.firebase.analytics.connector.internal.AnalyticsConnectorRegistrar;
import com.google.firebase.components.d;
import com.google.firebase.heartbeatinfo.e;
import com.google.gson.internal.n;
import com.onetrust.otpublishers.headless.Public.DataModel.OTConfiguration;
import com.onetrust.otpublishers.headless.Public.Keys.OTFragmentTags;
import com.onetrust.otpublishers.headless.UI.fragment.D;
import com.quizlet.data.model.C4129g0;
import com.quizlet.data.model.M1;
import com.quizlet.features.practicetest.common.data.PracticeTestConfigurationData;
import com.quizlet.generated.enums.EnumC4533y0;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b implements InterfaceC0127d, androidx.lifecycle.viewmodel.b, com.bumptech.glide.util.pool.a, m, c, r, d, n, com.google.android.gms.tasks.c {
    public static b b;
    public final /* synthetic */ int a;

    public /* synthetic */ b(int i) {
        this.a = i;
    }

    public static D a(com.onetrust.otpublishers.headless.Internal.Event.a aVar, OTConfiguration oTConfiguration) {
        Intrinsics.checkNotNullParameter(OTFragmentTags.OT_VENDOR_LIST_FRAGMENT_TAG, "fragmentTag");
        Bundle bundleA = AbstractC3206m6.a(new Pair(OTFragmentTags.FRAGMENT_TAG, OTFragmentTags.OT_VENDOR_LIST_FRAGMENT_TAG));
        D d = new D();
        d.setArguments(bundleA);
        d.s = aVar;
        d.t = oTConfiguration;
        return d;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:25:0x006b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void d(final com.facebook.appevents.e r10, com.facebook.appevents.b r11) {
        /*
            Method dump skipped, instructions count: 286
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.perf.logging.b.d(com.facebook.appevents.e, com.facebook.appevents.b):void");
    }

    public static Pair e(Bundle bundle, q qVar, boolean z) {
        String str = j.c() ? "1" : "0";
        Map map = q.b;
        Pair pairB = AbstractC3559x2.b("is_implicit_purchase_logging_enabled", str, bundle, qVar);
        Object objC = AbstractC3559x2.c("fb_iap_product_id", bundle, qVar);
        String str2 = objC instanceof String ? (String) objC : null;
        if (!z) {
            if ((bundle != null ? bundle.getString("fb_content_id") : null) == null && str2 != null) {
                Pair pairB2 = AbstractC3559x2.b("fb_content_id", str2, bundle, qVar);
                pairB = AbstractC3559x2.b("android_dynamic_ads_content_id", "client_manual", (Bundle) pairB2.a, (q) pairB2.b);
            }
        }
        Pair pairB3 = AbstractC3559x2.b("is_autolog_app_events_enabled", B.c() ? "1" : "0", (Bundle) pairB.a, (q) pairB.b);
        return new Pair((Bundle) pairB3.a, (q) pairB3.b);
    }

    public static int h() {
        int i;
        synchronized (com.facebook.appevents.j.c()) {
            i = !com.facebook.internal.instrument.crashshield.a.b(com.facebook.appevents.j.class) ? 1 : 0;
        }
        return i;
    }

    public static String i() {
        e callback = new e(8);
        Intrinsics.checkNotNullParameter(callback, "callback");
        if (!o.a().getSharedPreferences("com.facebook.sdk.appEventPreferences", 0).getBoolean("is_referrer_updated", false)) {
            InstallReferrerClient installReferrerClientBuild = InstallReferrerClient.newBuilder(o.a()).build();
            try {
                installReferrerClientBuild.startConnection(new com.quizlet.data.repository.school.membership.a(installReferrerClientBuild, callback));
            } catch (Exception unused) {
            }
        }
        return o.a().getSharedPreferences("com.facebook.sdk.appEventPreferences", 0).getString("install_referrer", null);
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x0032  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x003d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void j() {
        /*
            java.lang.Object r1 = com.facebook.appevents.j.c()
            monitor-enter(r1)
            java.util.concurrent.ScheduledThreadPoolExecutor r0 = com.facebook.appevents.j.b()     // Catch: java.lang.Throwable -> L45
            if (r0 == 0) goto Ld
            monitor-exit(r1)
            return
        Ld:
            java.util.concurrent.ScheduledThreadPoolExecutor r0 = new java.util.concurrent.ScheduledThreadPoolExecutor     // Catch: java.lang.Throwable -> L45
            r2 = 1
            r0.<init>(r2)     // Catch: java.lang.Throwable -> L45
            java.lang.Class<com.facebook.appevents.j> r2 = com.facebook.appevents.j.class
            boolean r3 = com.facebook.internal.instrument.crashshield.a.b(r2)     // Catch: java.lang.Throwable -> L45
            if (r3 == 0) goto L1c
            goto L23
        L1c:
            com.facebook.appevents.j.d = r0     // Catch: java.lang.Throwable -> L1f
            goto L23
        L1f:
            r0 = move-exception
            com.facebook.internal.instrument.crashshield.a.a(r2, r0)     // Catch: java.lang.Throwable -> L45
        L23:
            kotlin.Unit r0 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L45
            monitor-exit(r1)
            androidx.camera.camera2.internal.h r3 = new androidx.camera.camera2.internal.h
            r0 = 7
            r3.<init>(r0)
            java.util.concurrent.ScheduledThreadPoolExecutor r2 = com.facebook.appevents.j.b()
            if (r2 == 0) goto L3d
            java.util.concurrent.TimeUnit r8 = java.util.concurrent.TimeUnit.SECONDS
            r4 = 0
            r6 = 86400(0x15180, double:4.26873E-319)
            r2.scheduleAtFixedRate(r3, r4, r6, r8)
            return
        L3d:
            java.lang.String r0 = "Required value was null."
            java.lang.IllegalStateException r1 = new java.lang.IllegalStateException
            r1.<init>(r0)
            throw r1
        L45:
            r0 = move-exception
            monitor-exit(r1)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.perf.logging.b.j():void");
    }

    public static ArrayList k(PracticeTestConfigurationData configurationData) {
        Intrinsics.checkNotNullParameter(configurationData, "configurationData");
        ArrayList arrayList = new ArrayList();
        if (configurationData.b) {
            arrayList.add(EnumC4533y0.MCQ_WITH_SINGLE_ANSWER);
        }
        if (configurationData.c) {
            arrayList.add(EnumC4533y0.QUESTION_WITH_SHORT_FREE_RESPONSE);
        }
        return arrayList;
    }

    public static C4129g0 l(M1 studyMaterial, long j) {
        Intrinsics.checkNotNullParameter(studyMaterial, "studyMaterial");
        return new C4129g0(j, studyMaterial.c(), studyMaterial.b());
    }

    @Override // com.google.gson.internal.n
    public Object E() {
        return new LinkedHashMap();
    }

    @Override // androidx.camera.camera2.internal.InterfaceC0127d
    public CamcorderProfile b(int i, int i2) {
        return CamcorderProfile.get(i, i2);
    }

    @Override // com.bumptech.glide.util.pool.a
    public Object c() {
        return new u();
    }

    @Override // com.google.firebase.components.d
    public Object f(c0 c0Var) {
        return AnalyticsConnectorRegistrar.lambda$getComponents$0(c0Var);
    }

    @Override // androidx.camera.camera2.internal.InterfaceC0127d
    public boolean g(int i, int i2) {
        return CamcorderProfile.hasProfile(i, i2);
    }

    public void m(androidx.compose.foundation.text.input.internal.u uVar, float f) {
        androidx.cardview.widget.a aVar = (androidx.cardview.widget.a) ((Drawable) uVar.b);
        CardView cardView = (CardView) uVar.c;
        boolean useCompatPadding = cardView.getUseCompatPadding();
        boolean preventCornerOverlap = cardView.getPreventCornerOverlap();
        if (f != aVar.e || aVar.f != useCompatPadding || aVar.g != preventCornerOverlap) {
            aVar.e = f;
            aVar.f = useCompatPadding;
            aVar.g = preventCornerOverlap;
            aVar.b(null);
            aVar.invalidateSelf();
        }
        if (!cardView.getUseCompatPadding()) {
            uVar.s(0, 0, 0, 0);
            return;
        }
        androidx.cardview.widget.a aVar2 = (androidx.cardview.widget.a) ((Drawable) uVar.b);
        float f2 = aVar2.e;
        float f3 = aVar2.a;
        int iCeil = (int) Math.ceil(androidx.cardview.widget.b.a(f2, f3, cardView.getPreventCornerOverlap()));
        int iCeil2 = (int) Math.ceil(androidx.cardview.widget.b.b(f2, f3, cardView.getPreventCornerOverlap()));
        uVar.s(iCeil, iCeil2, iCeil, iCeil2);
    }

    @Override // com.google.android.gms.tasks.c
    public void t(Exception exc) {
        Log.e("OptionalModuleUtils", "Failed to request modules install request", exc);
    }

    @Override // com.google.android.gms.measurement.internal.r
    public Object zza() {
        switch (this.a) {
            case 10:
                List list = AbstractC3893t.a;
                Boolean bool = (Boolean) C2991f3.b.b();
                bool.getClass();
                return bool;
            case 11:
                List list2 = AbstractC3893t.a;
                W3.b.get();
                Boolean bool2 = (Boolean) Y3.e.b();
                bool2.getClass();
                return bool2;
            case 12:
                List list3 = AbstractC3893t.a;
                Boolean bool3 = (Boolean) b4.a.b();
                bool3.getClass();
                return bool3;
            case 13:
                List list4 = AbstractC3893t.a;
                O2.b.get();
                return Integer.valueOf((int) ((Long) Q2.p.b()).longValue());
            case 14:
                List list5 = AbstractC3893t.a;
                O2.b.get();
                Long l = (Long) Q2.N.b();
                l.getClass();
                return l;
            case 15:
                List list6 = AbstractC3893t.a;
                O2.b.get();
                return Integer.valueOf((int) ((Long) Q2.p0.b()).longValue());
            case 16:
                List list7 = AbstractC3893t.a;
                O2.b.get();
                return Integer.valueOf((int) ((Long) Q2.s.b()).longValue());
            default:
                List list8 = AbstractC3893t.a;
                Boolean bool4 = (Boolean) Z2.a.b();
                bool4.getClass();
                return bool4;
        }
    }

    public b(androidx.work.impl.model.e eVar, AbstractC1136h0 abstractC1136h0) {
        this.a = 7;
    }
}
