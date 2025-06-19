package com.google.android.gms.internal.ads;

import android.app.Application;
import android.content.Context;
import android.graphics.Bitmap;
import android.media.AudioManager;
import android.media.MediaFormat;
import android.media.MediaPlayer;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;
import android.text.TextUtils;
import android.view.View;
import android.view.ViewGroup;
import androidx.compose.material3.C0676l1;
import com.amazon.device.ads.DtbDeviceData;
import com.comscore.streaming.EventType;
import com.google.android.gms.ads.internal.client.C1614q;
import com.google.android.gms.ads.internal.overlay.AdOverlayInfoParcel;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.common.GooglePlayServicesNotAvailableException;
import com.google.android.gms.common.GooglePlayServicesRepairableException;
import com.google.android.gms.internal.measurement.C3008j0;
import com.google.android.gms.internal.measurement.C3083y1;
import com.onetrust.otpublishers.headless.Public.Keys.OTUXParamsKeys;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicInteger;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class Qv implements Runnable {
    public final /* synthetic */ int a;
    public final Object b;
    public final Object c;

    public /* synthetic */ Qv(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    private final void a() throws com.google.android.gms.ads.internal.util.client.zzr {
        InterfaceC1717Je c1699Ge;
        Context context = (Context) this.b;
        AbstractC2773w7.a(context);
        C2601s7 c2601s7 = AbstractC2773w7.B0;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            return;
        }
        Bundle bundle = new Bundle();
        C2601s7 c2601s72 = AbstractC2773w7.q0;
        SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
        bundle.putBoolean("measurementEnabled", ((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s72)).booleanValue());
        if (((Boolean) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(AbstractC2773w7.x0)).booleanValue()) {
            bundle.putString("ad_storage", "denied");
            bundle.putString("analytics_storage", "denied");
        }
        androidx.appcompat.app.Q q = C3008j0.f(context, "FA-Ads", "am", (String) this.c, bundle).d;
        try {
            try {
                IBinder iBinderB = com.google.android.gms.ads.internal.util.client.i.b(context).b("com.google.android.gms.ads.measurement.DynamiteMeasurementManager");
                int i = AbstractBinderC1705He.a;
                if (iBinderB == null) {
                    c1699Ge = null;
                } else {
                    IInterface iInterfaceQueryLocalInterface = iBinderB.queryLocalInterface("com.google.android.gms.ads.measurement.IMeasurementManager");
                    c1699Ge = iInterfaceQueryLocalInterface instanceof InterfaceC1717Je ? (InterfaceC1717Je) iInterfaceQueryLocalInterface : new C1699Ge(iBinderB, "com.google.android.gms.ads.measurement.IMeasurementManager", 0);
                }
                com.google.android.gms.dynamic.b bVar = new com.google.android.gms.dynamic.b(context);
                C9 c9 = new C9(q);
                C1699Ge c1699Ge2 = (C1699Ge) c1699Ge;
                Parcel parcelF3 = c1699Ge2.f3();
                AbstractC2857y5.e(parcelF3, bVar);
                AbstractC2857y5.e(parcelF3, c9);
                c1699Ge2.d4(2, parcelF3);
            } catch (Exception e) {
                throw new com.google.android.gms.ads.internal.util.client.zzr(e);
            }
        } catch (RemoteException e2) {
            e = e2;
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        } catch (com.google.android.gms.ads.internal.util.client.zzr e3) {
            e = e3;
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        } catch (NullPointerException e4) {
            e = e4;
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        }
    }

    private final void b() {
        C1673Cc c1673Cc = (C1673Cc) this.b;
        Bitmap bitmap = (Bitmap) this.c;
        C2905zA c2905zA = BA.b;
        AA aa = new AA();
        bitmap.compress(Bitmap.CompressFormat.PNG, 0, aa);
        synchronized (c1673Cc.h) {
            KB kb = c1673Cc.a;
            C2002eC c2002eCW = C2090gC.w();
            BA baA = aa.a();
            c2002eCW.e();
            C2090gC.x((C2090gC) c2002eCW.b, baA);
            c2002eCW.e();
            C2090gC.y((C2090gC) c2002eCW.b);
            c2002eCW.e();
            C2090gC.z((C2090gC) c2002eCW.b);
            C2090gC c2090gC = (C2090gC) c2002eCW.c();
            kb.e();
            C2392nC.I((C2392nC) kb.b, c2090gC);
        }
    }

    private final void c() throws IllegalStateException {
        C2743ve c2743ve;
        MediaPlayer mediaPlayer;
        MediaFormat format;
        boolean zBooleanValue = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.T1)).booleanValue();
        TextureViewSurfaceTextureListenerC2613sd textureViewSurfaceTextureListenerC2613sd = (TextureViewSurfaceTextureListenerC2613sd) this.c;
        if (zBooleanValue && (c2743ve = textureViewSurfaceTextureListenerC2613sd.c) != null && (mediaPlayer = (MediaPlayer) this.b) != null) {
            try {
                MediaPlayer.TrackInfo[] trackInfo = mediaPlayer.getTrackInfo();
                if (trackInfo != null) {
                    HashMap map = new HashMap();
                    for (MediaPlayer.TrackInfo trackInfo2 : trackInfo) {
                        if (trackInfo2 != null) {
                            int trackType = trackInfo2.getTrackType();
                            if (trackType == 1) {
                                MediaFormat format2 = trackInfo2.getFormat();
                                if (format2 != null) {
                                    if (format2.containsKey("frame-rate")) {
                                        try {
                                            map.put("frameRate", String.valueOf(format2.getFloat("frame-rate")));
                                        } catch (ClassCastException unused) {
                                            map.put("frameRate", String.valueOf(format2.getInteger("frame-rate")));
                                        }
                                    }
                                    if (format2.containsKey("bitrate")) {
                                        Integer numValueOf = Integer.valueOf(format2.getInteger("bitrate"));
                                        textureViewSurfaceTextureListenerC2613sd.s = numValueOf;
                                        map.put("bitRate", String.valueOf(numValueOf));
                                    }
                                    if (format2.containsKey(OTUXParamsKeys.OT_UX_WIDTH) && format2.containsKey(OTUXParamsKeys.OT_UX_HEIGHT)) {
                                        map.put("resolution", format2.getInteger(OTUXParamsKeys.OT_UX_WIDTH) + "x" + format2.getInteger(OTUXParamsKeys.OT_UX_HEIGHT));
                                    }
                                    if (format2.containsKey("mime")) {
                                        map.put("videoMime", format2.getString("mime"));
                                    }
                                    if (Build.VERSION.SDK_INT >= 30 && format2.containsKey("codecs-string")) {
                                        map.put("videoCodec", format2.getString("codecs-string"));
                                    }
                                }
                            } else if (trackType == 2 && (format = trackInfo2.getFormat()) != null) {
                                if (format.containsKey("mime")) {
                                    map.put("audioMime", format.getString("mime"));
                                }
                                if (Build.VERSION.SDK_INT >= 30 && format.containsKey("codecs-string")) {
                                    map.put("audioCodec", format.getString("codecs-string"));
                                }
                            }
                        }
                    }
                    if (!map.isEmpty()) {
                        c2743ve.j("onMetadataEvent", map);
                    }
                }
            } catch (RuntimeException e) {
                com.google.android.gms.ads.internal.j.C.h.h("AdMediaPlayerView.reportMetadata", e);
            }
        }
        C2785wd c2785wd = textureViewSurfaceTextureListenerC2613sd.q;
        if (c2785wd != null) {
            c2785wd.g();
        }
    }

    private final void d() {
        InterfaceC2529qe interfaceC2529qe;
        Os os = new Os((C2743ve) this.b, 13);
        C2622sm c2622sm = (C2622sm) this.c;
        synchronized (c2622sm) {
            com.quizlet.data.repository.studysetwithcreatorinclass.g gVar = c2622sm.f;
            if (gVar == null || (interfaceC2529qe = c2622sm.d) == null) {
                return;
            }
            com.google.android.gms.ads.internal.j.C.x.getClass();
            C2147hi.p(new RunnableC2793wl(3, gVar, os));
            c2622sm.f = null;
            interfaceC2529qe.G0(null);
        }
    }

    private final void e() {
        ((BinderC2915ze) this.b).a.j("pubVideoCmd", (HashMap) this.c);
    }

    private final void f() {
        Uri uri = Uri.parse((String) this.c);
        C1669Be c1669Be = ((ViewTreeObserverOnGlobalLayoutListenerC2829xe) ((C1663Ae) this.b).b.b).n;
        if (c1669Be == null) {
            com.google.android.gms.ads.internal.util.client.i.e("Unable to pass GMSG, no AdWebViewClient for AdWebView!");
        } else {
            c1669Be.X(uri);
        }
    }

    private final void g() {
        AbstractC1795We.a = (AudioManager) ((Context) this.b).getSystemService("audio");
        ((C1973dj) this.c).c();
    }

    private final void h() {
        JSONObject jSONObject = (JSONObject) this.c;
        com.google.android.gms.ads.internal.util.client.i.d("Calling AFMA_updateActiveView(" + jSONObject.toString() + ")");
        ((C1736Mf) this.b).a.d("AFMA_updateActiveView", jSONObject);
    }

    private final void i() {
        try {
            ((Xh) this.b).mo16b(this.c);
        } catch (Throwable th) {
            com.google.android.gms.ads.internal.j.C.h.g("EventEmitter.notify", th);
            com.google.android.gms.ads.internal.util.A.m();
        }
    }

    private final void j() {
        com.quizlet.data.interactor.progress.c cVar = (com.quizlet.data.interactor.progress.c) this.b;
        Integer num = (Integer) cVar.c;
        Integer num2 = (Integer) this.c;
        cVar.c = num2;
        if (num.equals(num2)) {
            return;
        }
        Lr lr = (Lr) cVar.d;
        lr.getClass();
        C2221jD c2221jD = (C2221jD) lr.b;
        c2221jD.U();
        c2221jD.u1(1, 10, num2);
        c2221jD.u1(2, 10, num2);
        C2047fD c2047fD = new C2047fD(2);
        com.amazon.aps.ads.privacy.a aVar = c2221jD.m;
        aVar.d(21, c2047fD);
        aVar.c();
    }

    private final void k() {
        View view;
        C2191ij c2191ij = (C2191ij) this.b;
        Yi yi = c2191ij.d;
        synchronized (yi) {
            view = yi.o;
        }
        if (view != null) {
            boolean z = ((ViewGroup) this.c) != null;
            int iG = yi.g();
            C2023eq c2023eq = c2191ij.b;
            com.google.android.gms.ads.internal.util.C c = c2191ij.a;
            if (iG == 2 || yi.g() == 1) {
                c.e(c2023eq.f, String.valueOf(yi.g()), z);
            } else if (yi.g() == 6) {
                String str = c2023eq.f;
                c.e(str, "2", z);
                c.e(str, "1", z);
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:126:0x0285  */
    /* JADX WARN: Type inference failed for: r3v1, types: [com.google.android.gms.internal.ads.uj, com.google.android.gms.internal.ads.x5] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private final void l() {
        /*
            Method dump skipped, instructions count: 675
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.Qv.l():void");
    }

    private final void m() {
        ((C1931cl) this.b).i.execute(new RunnableC2104gj((C2313ld) this.c, 2));
    }

    private final void n() {
        C1931cl c1931cl = (C1931cl) this.b;
        try {
            ((K9) this.c).S2(c1931cl.a());
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.f("", e);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:64:0x0187 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private final void o() throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 469
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.Qv.o():void");
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // java.lang.Runnable
    public final void run() throws Throwable {
        Throwable thC;
        C1964da c1964da;
        DataOutputStream dataOutputStream;
        JSONObject jSONObject;
        JSONObject jSONObject2;
        int i = 0;
        int i2 = 8;
        Application application = null;
        DataOutputStream dataOutputStream2 = null;
        DataOutputStream dataOutputStream3 = null;
        B5 c2900z5 = null;
        switch (this.a) {
            case 0:
                com.google.common.util.concurrent.e eVar = (com.google.common.util.concurrent.e) this.b;
                boolean z = eVar instanceof AbstractC2246jw;
                Pv pv = (Pv) this.c;
                if (z && (thC = ((AbstractC2246jw) eVar).c()) != null) {
                    pv.zza(thC);
                    return;
                }
                try {
                    pv.mo15c(AbstractC2025es.P(eVar));
                    return;
                } catch (ExecutionException e) {
                    pv.zza(e.getCause());
                    return;
                } catch (Throwable th) {
                    pv.zza(th);
                    return;
                }
            case 1:
                String str = Yo.a;
                com.amazon.aps.ads.privacy.a aVar = ((SurfaceHolderCallbackC2091gD) ((Fi) this.b).c).a.m;
                aVar.d(25, new Lr((C1740Nd) this.c, i2));
                aVar.c();
                return;
            case 2:
                Fi fi = (Fi) this.b;
                QC qc = (QC) this.c;
                synchronized (qc) {
                }
                String str2 = Yo.a;
                WD wd = ((SurfaceHolderCallbackC2091gD) fi.c).a.r;
                RD rdJ = wd.j((C2093gF) wd.d.e);
                wd.i(rdJ, 1020, new Lr(rdJ, qc));
                return;
            case 3:
                try {
                    ((C2726v3) this.c).b.put((B3) this.b);
                    return;
                } catch (InterruptedException unused) {
                    Thread.currentThread().interrupt();
                    return;
                }
            case 4:
                N5 n5 = (N5) this.c;
                View view = (View) this.b;
                try {
                    J5 j5 = new J5(n5.f, n5.g, n5.h, n5.i, n5.j, n5.k, n5.l, n5.o);
                    C3083y1 c3083y1 = com.google.android.gms.ads.internal.j.C.g;
                    synchronized (c3083y1.c) {
                        K5 k5 = (K5) c3083y1.d;
                        if (k5 != null) {
                            application = k5.b;
                        }
                    }
                    if (application != null) {
                        String str3 = n5.m;
                        if (!TextUtils.isEmpty(str3)) {
                            String str4 = (String) view.getTag(application.getResources().getIdentifier((String) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.c0), "id", application.getPackageName()));
                            if (str4 != null && str4.equals(str3)) {
                                return;
                            }
                        }
                    }
                    C0676l1 c0676l1A = n5.a(view, j5);
                    j5.b();
                    if (c0676l1A.a == 0 && c0676l1A.b == 0) {
                        return;
                    }
                    int i3 = c0676l1A.b;
                    if (i3 != 0) {
                        if (i3 == 0) {
                        }
                        n5.d.e(j5);
                        return;
                    } else if (j5.k == 0) {
                        return;
                    }
                    I3 i32 = n5.d;
                    synchronized (i32.c) {
                        try {
                            if (((LinkedList) i32.d).contains(j5)) {
                                return;
                            }
                            n5.d.e(j5);
                            return;
                        } finally {
                        }
                    }
                } catch (Exception e2) {
                    com.google.android.gms.ads.internal.util.client.i.f("Exception in fetchContentOnUIThread", e2);
                    com.google.android.gms.ads.internal.j.C.h.h("ContentFetchTask.fetchContent", e2);
                    return;
                }
            case 5:
                if (((C2257k6) this.c).isCancelled()) {
                    ((com.google.common.util.concurrent.e) this.b).cancel(true);
                    return;
                }
                return;
            case 6:
                boolean zBooleanValue = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.e5)).booleanValue();
                C2472p6 c2472p6 = (C2472p6) this.b;
                Context context = (Context) this.c;
                if (zBooleanValue) {
                    try {
                        try {
                            IBinder iBinderB = com.google.android.gms.ads.internal.util.client.i.b(context).b("com.google.android.gms.ads.clearcut.DynamiteClearcutLogger");
                            int i4 = A5.a;
                            if (iBinderB != null) {
                                IInterface iInterfaceQueryLocalInterface = iBinderB.queryLocalInterface("com.google.android.gms.ads.clearcut.IClearcut");
                                c2900z5 = iInterfaceQueryLocalInterface instanceof B5 ? (B5) iInterfaceQueryLocalInterface : new C2900z5(iBinderB, "com.google.android.gms.ads.clearcut.IClearcut", 0);
                            }
                            c2472p6.a = c2900z5;
                            ((C2900z5) c2472p6.a).h4(new com.google.android.gms.dynamic.b(context));
                            c2472p6.b = true;
                            return;
                        } catch (Exception e3) {
                            throw new com.google.android.gms.ads.internal.util.client.zzr(e3);
                        }
                    } catch (RemoteException | com.google.android.gms.ads.internal.util.client.zzr | NullPointerException unused2) {
                        com.google.android.gms.ads.internal.util.client.i.d("Cannot dynamite load clearcut");
                        return;
                    }
                }
                return;
            case 7:
                C2007ea c2007ea = (C2007ea) this.b;
                C1964da c1964da2 = (C1964da) this.c;
                com.google.android.gms.ads.internal.j.C.k.getClass();
                long jCurrentTimeMillis = System.currentTimeMillis();
                ArrayList arrayList = new ArrayList();
                try {
                    com.google.android.gms.ads.internal.util.A.l("loadJavascriptEngine > Before createJavascriptEngine");
                    c1964da = c1964da2;
                    try {
                        V9 v9 = new V9((Context) c2007ea.d, (VersionInfoParcel) c2007ea.e);
                        com.google.android.gms.ads.internal.util.A.l("loadJavascriptEngine > After createJavascriptEngine");
                        com.google.android.gms.ads.internal.util.A.l("loadJavascriptEngine > Before setting new engine loaded listener");
                        androidx.work.impl.background.greedy.d dVar = new androidx.work.impl.background.greedy.d();
                        dVar.b = c2007ea;
                        dVar.c = arrayList;
                        dVar.a = jCurrentTimeMillis;
                        dVar.d = c1964da;
                        dVar.e = v9;
                        v9.a.L().h = new Os(dVar, i2);
                        com.google.android.gms.ads.internal.util.A.l("loadJavascriptEngine > Before registering GmsgHandler for /jsLoaded");
                        v9.q("/jsLoaded", new Z9(c2007ea, jCurrentTimeMillis, c1964da, v9));
                        androidx.appcompat.app.L l = new androidx.appcompat.app.L(19);
                        C1833aa c1833aa = new C1833aa(c2007ea, v9, l);
                        l.b = c1833aa;
                        com.google.android.gms.ads.internal.util.A.l("loadJavascriptEngine > Before registering GmsgHandler for /requestReload");
                        v9.q("/requestReload", c1833aa);
                        String str5 = (String) c2007ea.a;
                        com.google.android.gms.ads.internal.util.A.l("loadJavascriptEngine > javascriptPath: ".concat(String.valueOf(str5)));
                        if (str5.endsWith(".js")) {
                            com.google.android.gms.ads.internal.util.A.l("loadJavascriptEngine > Before newEngine.loadJavascript");
                            com.google.android.gms.ads.internal.util.A.l("loadJavascript on adWebView from path: ".concat(str5));
                            V9.c(new T9(v9, "<!DOCTYPE html><html><head><script src=\"" + str5 + "\"></script></head><body></body></html>", 3));
                            com.google.android.gms.ads.internal.util.A.l("loadJavascriptEngine > After newEngine.loadJavascript");
                        } else if (str5.startsWith("<html>")) {
                            com.google.android.gms.ads.internal.util.A.l("loadJavascriptEngine > Before newEngine.loadHtml");
                            com.google.android.gms.ads.internal.util.A.l("loadHtml on adWebView from html");
                            V9.c(new T9(v9, str5, 2));
                            com.google.android.gms.ads.internal.util.A.l("loadJavascriptEngine > After newEngine.loadHtml");
                        } else {
                            com.google.android.gms.ads.internal.util.A.l("loadJavascriptEngine > Before newEngine.loadHtmlWrapper");
                            com.google.android.gms.ads.internal.util.A.l("loadHtmlWrapper on adWebView from path: ".concat(str5));
                            V9.c(new T9(v9, str5, i));
                            com.google.android.gms.ads.internal.util.A.l("loadJavascriptEngine > After newEngine.loadHtmlWrapper");
                        }
                        com.google.android.gms.ads.internal.util.A.l("loadJavascriptEngine > Before calling ADMOB_UI_HANDLER.postDelayed");
                        com.google.android.gms.ads.internal.util.F.l.postDelayed(new Y9(c2007ea, c1964da, v9, arrayList, jCurrentTimeMillis, 1), ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.d)).intValue());
                        return;
                    } catch (Throwable th2) {
                        th = th2;
                        com.google.android.gms.ads.internal.util.client.i.f("Error creating webview.", th);
                        C2601s7 c2601s7 = AbstractC2773w7.J7;
                        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                        if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
                            c1964da.t("SdkJavascriptFactory.loadJavascriptEngine.createJavascriptEngine", th);
                            return;
                        } else if (((Boolean) rVar.c.a(AbstractC2773w7.L7)).booleanValue()) {
                            com.google.android.gms.ads.internal.j.C.h.g("SdkJavascriptFactory.loadJavascriptEngine", th);
                            c1964da.s();
                            return;
                        } else {
                            com.google.android.gms.ads.internal.j.C.h.h("SdkJavascriptFactory.loadJavascriptEngine", th);
                            c1964da.s();
                            return;
                        }
                    }
                } catch (Throwable th3) {
                    th = th3;
                    c1964da = c1964da2;
                }
            case 8:
                a();
                return;
            case 9:
                assistantMode.utils.studiableMetadata.b bVar = com.google.android.gms.ads.internal.j.C.b;
                assistantMode.utils.studiableMetadata.b.a0(((zzbsd) this.c).a, (AdOverlayInfoParcel) this.b, true, null);
                return;
            case 10:
                ((com.google.android.gms.ads.internal.util.client.k) this.b).zza((String) this.c);
                return;
            case 11:
                ParcelFileDescriptor.AutoCloseOutputStream autoCloseOutputStream = (ParcelFileDescriptor.AutoCloseOutputStream) this.b;
                byte[] bArr = (byte[]) this.c;
                try {
                    try {
                        dataOutputStream = new DataOutputStream(autoCloseOutputStream);
                    } catch (Throwable th4) {
                        th = th4;
                    }
                } catch (IOException e4) {
                    e = e4;
                }
                try {
                    int length = bArr.length;
                    dataOutputStream.writeInt(length);
                    dataOutputStream.write(bArr);
                    com.google.android.gms.common.util.c.d(dataOutputStream);
                    dataOutputStream3 = length;
                } catch (IOException e5) {
                    e = e5;
                    dataOutputStream2 = dataOutputStream;
                    com.google.android.gms.ads.internal.util.client.i.f("Error transporting the ad response", e);
                    com.google.android.gms.ads.internal.j.C.h.h("LargeParcelTeleporter.pipeData.1", e);
                    if (dataOutputStream2 == null) {
                        com.google.android.gms.common.util.c.d(autoCloseOutputStream);
                        dataOutputStream3 = dataOutputStream2;
                    } else {
                        com.google.android.gms.common.util.c.d(dataOutputStream2);
                        dataOutputStream3 = dataOutputStream2;
                    }
                    return;
                } catch (Throwable th5) {
                    th = th5;
                    dataOutputStream3 = dataOutputStream;
                    if (dataOutputStream3 == null) {
                        com.google.android.gms.common.util.c.d(autoCloseOutputStream);
                    } else {
                        com.google.android.gms.common.util.c.d(dataOutputStream3);
                    }
                    throw th;
                }
                return;
            case 12:
                b();
                return;
            case 13:
                C2313ld c2313ld = (C2313ld) this.c;
                try {
                    c2313ld.c(com.google.android.gms.ads.identifier.b.a((Context) this.b));
                    return;
                } catch (GooglePlayServicesNotAvailableException | GooglePlayServicesRepairableException | IOException | IllegalStateException e6) {
                    c2313ld.d(e6);
                    com.google.android.gms.ads.internal.util.client.i.f("Exception while getting advertising Id info", e6);
                    return;
                }
            case 14:
                c();
                return;
            case 15:
                AtomicInteger atomicInteger = C2143he.u;
                ((InterfaceC2529qe) this.b).j("onGcacheInfoEvent", (HashMap) this.c);
                return;
            case 16:
                d();
                return;
            case 17:
                super/*android.webkit.WebView*/.loadUrl((String) this.c);
                return;
            case 18:
                e();
                return;
            case 19:
                f();
                return;
            case 20:
                g();
                return;
            case 21:
                h();
                return;
            case EventType.WINDOW_STATE /* 22 */:
                i();
                return;
            case EventType.AUDIO /* 23 */:
                j();
                return;
            case EventType.VIDEO /* 24 */:
                k();
                return;
            case EventType.SUBS /* 25 */:
                l();
                return;
            case EventType.CDN /* 26 */:
                m();
                return;
            case 27:
                n();
                return;
            case 28:
                o();
                return;
            default:
                C2536ql c2536ql = (C2536ql) this.b;
                String str6 = (String) this.c;
                C2493pl c2493pl = c2536ql.c;
                synchronized (c2493pl) {
                    try {
                        jSONObject = new JSONObject();
                        jSONObject.put("platform", "ANDROID");
                        String str7 = c2493pl.k;
                        if (!TextUtils.isEmpty(str7)) {
                            jSONObject.put("sdkVersion", "afma-sdk-a-v" + str7);
                        }
                        jSONObject.put("internalSdkVersion", c2493pl.i);
                        jSONObject.put(DtbDeviceData.DEVICE_DATA_OS_VERSION_KEY, Build.VERSION.RELEASE);
                        jSONObject.put("adapters", c2493pl.d.a());
                        C2601s7 c2601s72 = AbstractC2773w7.u9;
                        com.google.android.gms.ads.internal.client.r rVar2 = com.google.android.gms.ads.internal.client.r.d;
                        if (((Boolean) rVar2.c.a(c2601s72)).booleanValue()) {
                            String str8 = com.google.android.gms.ads.internal.j.C.h.g;
                            if (!TextUtils.isEmpty(str8)) {
                                jSONObject.put("plugin", str8);
                            }
                        }
                        long j = c2493pl.q;
                        com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
                        jVar.k.getClass();
                        if (j < System.currentTimeMillis() / 1000) {
                            c2493pl.o = "{}";
                        }
                        jSONObject.put("networkExtras", c2493pl.o);
                        jSONObject.put("adSlots", c2493pl.g());
                        jSONObject.put("appInfo", c2493pl.e.a());
                        String str9 = jVar.h.d().n().e;
                        if (!TextUtils.isEmpty(str9)) {
                            jSONObject.put("cld", new JSONObject(str9));
                        }
                        if (((Boolean) rVar2.c.a(AbstractC2773w7.k9)).booleanValue() && (jSONObject2 = c2493pl.p) != null) {
                            com.google.android.gms.ads.internal.util.client.i.d("Server data: " + jSONObject2.toString());
                            jSONObject.put("serverData", c2493pl.p);
                        }
                        if (((Boolean) rVar2.c.a(AbstractC2773w7.j9)).booleanValue()) {
                            jSONObject.put("openAction", c2493pl.v);
                            jSONObject.put("gesture", c2493pl.r);
                        }
                        jSONObject.put("isGamRegisteredTestDevice", jVar.o.g());
                        com.google.android.gms.ads.internal.util.client.c cVar = C1614q.f.a;
                        jSONObject.put("isSimulator", com.google.android.gms.ads.internal.util.client.c.l());
                        if (((Boolean) rVar2.c.a(AbstractC2773w7.w9)).booleanValue()) {
                            jSONObject.put("uiStorage", new JSONObject(c2493pl.x));
                        }
                        if (!TextUtils.isEmpty((CharSequence) rVar2.c.a(AbstractC2773w7.y9))) {
                            jSONObject.put("gmaDisk", (JSONObject) c2493pl.h.b);
                        }
                        if (!TextUtils.isEmpty((CharSequence) rVar2.c.a(AbstractC2773w7.x9))) {
                            jSONObject.put("userDisk", (JSONObject) c2493pl.g.b);
                        }
                    } catch (JSONException e7) {
                        com.google.android.gms.ads.internal.j.C.h.g("Inspector.toJson", e7);
                        com.google.android.gms.ads.internal.util.client.i.i("Ad inspector encountered an error", e7);
                    } finally {
                    }
                }
                if (!TextUtils.isEmpty(str6)) {
                    try {
                        jSONObject.put("redirectUrl", str6);
                    } catch (JSONException unused3) {
                    }
                }
                c2536ql.d.zzb("window.inspectorInfo", jSONObject.toString());
                return;
        }
    }

    public String toString() {
        switch (this.a) {
            case 0:
                C2326lq c2326lq = new C2326lq(Qv.class.getSimpleName(), 28);
                Fp fp = new Fp(5);
                ((Fp) c2326lq.d).c = fp;
                c2326lq.d = fp;
                fp.b = (Pv) this.c;
                return c2326lq.toString();
            default:
                return super.toString();
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public /* synthetic */ Qv(C2191ij c2191ij, InterfaceViewOnClickListenerC2705uj interfaceViewOnClickListenerC2705uj) {
        this.a = 25;
        this.b = c2191ij;
        this.c = (AbstractBinderC2814x5) interfaceViewOnClickListenerC2705uj;
    }

    public /* synthetic */ Qv(Object obj, boolean z, Object obj2, int i) {
        this.a = i;
        this.b = obj2;
        this.c = obj;
    }
}
