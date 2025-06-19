package com.google.android.gms.ads.internal.util;

import android.content.Context;
import android.content.SharedPreferences;
import android.text.TextUtils;
import android.webkit.WebSettings;
import com.google.android.gms.ads.nonagon.signalgeneration.C1635a;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.mlkit_vision_common.F4;
import com.google.android.gms.internal.mlkit_vision_common.G4;
import com.google.android.gms.internal.mlkit_vision_common.N4;
import com.google.android.gms.internal.mlkit_vision_common.O4;
import com.google.android.gms.measurement.internal.BinderC3869g0;
import com.google.android.gms.measurement.internal.C3874j;
import com.google.android.gms.measurement.internal.C3881m0;
import com.google.android.gms.measurement.internal.EnumC3879l0;
import com.google.android.gms.measurement.internal.r1;
import com.google.android.gms.measurement.internal.zzap;
import com.google.android.gms.measurement.internal.zzr;
import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.Callable;

/* loaded from: classes2.dex */
public final /* synthetic */ class y implements Callable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ y(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // java.util.concurrent.Callable
    public final Object call() throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        SharedPreferences sharedPreferences;
        G4 g4;
        boolean z = false;
        Object obj = this.b;
        Object obj2 = this.c;
        switch (this.a) {
            case 0:
                Context context = (Context) obj;
                Context context2 = (Context) obj2;
                if (context != null) {
                    A.l("Attempting to read user agent from Google Play Services.");
                    sharedPreferences = context.getSharedPreferences("admob_user_agent", 0);
                } else {
                    A.l("Attempting to read user agent from local cache.");
                    sharedPreferences = context2.getSharedPreferences("admob_user_agent", 0);
                    z = true;
                }
                String string = sharedPreferences.getString("user_agent", "");
                if (TextUtils.isEmpty(string)) {
                    A.l("Reading user agent from WebSettings");
                    string = WebSettings.getDefaultUserAgent(context2);
                    if (z) {
                        sharedPreferences.edit().putString("user_agent", string).apply();
                        A.l("Persisting user agent.");
                    }
                }
                return string;
            case 1:
                B b = F.l;
                WebSettings webSettings = (WebSettings) obj2;
                webSettings.setDatabasePath(((Context) obj).getDatabasePath("com.google.android.gms.ads.db").getAbsolutePath());
                webSettings.setDatabaseEnabled(true);
                webSettings.setDomStorageEnabled(true);
                webSettings.setDisplayZoomControls(false);
                webSettings.setBuiltInZoomControls(true);
                webSettings.setSupportZoom(true);
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Q0)).booleanValue()) {
                    webSettings.setTextZoom(100);
                }
                webSettings.setAllowContentAccess(false);
                return Boolean.TRUE;
            case 2:
                return ((com.google.android.gms.ads.internal.e) obj2).j((Context) obj);
            case 3:
                return ((C1635a) obj).getClickSignals((String) obj2);
            case 4:
                BinderC3869g0 binderC3869g0 = (BinderC3869g0) obj2;
                binderC3869g0.a.j();
                C3874j c3874j = binderC3869g0.a.c;
                r1.L(c3874j);
                return c3874j.a0((String) obj);
            case 5:
                BinderC3869g0 binderC3869g02 = (BinderC3869g0) obj2;
                binderC3869g02.a.j();
                return new zzap(binderC3869g02.a.d0(((zzr) obj).a));
            case 6:
                zzr zzrVar = (zzr) obj;
                String str = zzrVar.a;
                com.google.android.gms.common.internal.u.h(str);
                r1 r1Var = (r1) obj2;
                C3881m0 c3881m0N0 = r1Var.n0(str);
                EnumC3879l0 enumC3879l0 = EnumC3879l0.ANALYTICS_STORAGE;
                if (c3881m0N0.k(enumC3879l0) && C3881m0.e(100, zzrVar.u).k(enumC3879l0)) {
                    return r1Var.f0(zzrVar).d();
                }
                r1Var.c().o.f("Analytics storage consent denied. Returning null app instance id");
                return null;
            default:
                com.google.mlkit.vision.common.a aVar = (com.google.mlkit.vision.common.a) obj2;
                com.google.mlkit.vision.barcode.internal.c cVar = (com.google.mlkit.vision.barcode.internal.c) obj;
                HashMap map = G4.f;
                O4.b();
                int i = N4.a;
                O4.b();
                if (Boolean.parseBoolean("")) {
                    HashMap map2 = G4.f;
                    if (map2.get("detectorTaskWithResource#run") == null) {
                        map2.put("detectorTaskWithResource#run", new G4("detectorTaskWithResource#run"));
                    }
                    g4 = (G4) map2.get("detectorTaskWithResource#run");
                } else {
                    g4 = F4.g;
                }
                g4.a();
                try {
                    List listB = cVar.b.b(aVar);
                    g4.close();
                    return listB;
                } catch (Throwable th) {
                    try {
                        g4.close();
                    } catch (Throwable th2) {
                        try {
                            Throwable.class.getDeclaredMethod("addSuppressed", Throwable.class).invoke(th, th2);
                        } catch (Exception unused) {
                        }
                    }
                    throw th;
                }
        }
    }

    public /* synthetic */ y(Object obj, boolean z, Object obj2, int i) {
        this.a = i;
        this.c = obj;
        this.b = obj2;
    }
}
