package com.google.android.gms.internal.ads;

import android.app.Activity;
import android.content.Context;
import android.os.RemoteException;
import android.webkit.WebView;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

/* loaded from: classes2.dex */
public final class Di implements Xg, InterfaceC2015ei {
    public final C1727Lc a;
    public final Context b;
    public final C1739Nc c;
    public final WebView d;
    public String e;
    public final EnumC2515q6 f;

    public Di(C1727Lc c1727Lc, Context context, C1739Nc c1739Nc, WebView webView, EnumC2515q6 enumC2515q6) {
        this.a = c1727Lc;
        this.b = context;
        this.c = c1739Nc;
        this.d = webView;
        this.f = enumC2515q6;
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void a() {
        this.a.a(false);
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void b() {
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void f() {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2015ei
    public final void i() {
        EnumC2515q6 enumC2515q6 = EnumC2515q6.APP_OPEN;
        EnumC2515q6 enumC2515q62 = this.f;
        if (enumC2515q62 == enumC2515q6) {
            return;
        }
        C1739Nc c1739Nc = this.c;
        Context context = this.b;
        String str = "";
        if (c1739Nc.e(context)) {
            AtomicReference atomicReference = c1739Nc.f;
            if (c1739Nc.m(context, "com.google.android.gms.measurement.AppMeasurement", atomicReference, true)) {
                try {
                    String str2 = (String) c1739Nc.i(context, "getCurrentScreenName").invoke(atomicReference.get(), null);
                    if (str2 == null) {
                        str2 = (String) c1739Nc.i(context, "getCurrentScreenClass").invoke(atomicReference.get(), null);
                    }
                    if (str2 != null) {
                        str = str2;
                    }
                } catch (Exception unused) {
                    c1739Nc.l("getCurrentScreenName", false);
                }
            }
        }
        this.e = str;
        this.e = String.valueOf(str).concat(enumC2515q62 == EnumC2515q6.REWARD_BASED_VIDEO_AD ? "/Rewarded" : "/Interstitial");
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void q() throws IllegalAccessException, NoSuchMethodException, SecurityException, IllegalArgumentException, InvocationTargetException {
        WebView webView = this.d;
        if (webView != null && this.e != null) {
            Context context = webView.getContext();
            String str = this.e;
            C1739Nc c1739Nc = this.c;
            if (c1739Nc.e(context) && (context instanceof Activity)) {
                AtomicReference atomicReference = c1739Nc.g;
                if (c1739Nc.m(context, "com.google.firebase.analytics.FirebaseAnalytics", atomicReference, false)) {
                    ConcurrentHashMap concurrentHashMap = c1739Nc.h;
                    Method declaredMethod = (Method) concurrentHashMap.get("setCurrentScreen");
                    if (declaredMethod == null) {
                        try {
                            declaredMethod = context.getClassLoader().loadClass("com.google.firebase.analytics.FirebaseAnalytics").getDeclaredMethod("setCurrentScreen", Activity.class, String.class, String.class);
                            concurrentHashMap.put("setCurrentScreen", declaredMethod);
                        } catch (Exception unused) {
                            c1739Nc.l("setCurrentScreen", false);
                            declaredMethod = null;
                        }
                    }
                    try {
                        declaredMethod.invoke(atomicReference.get(), (Activity) context, str, context.getPackageName());
                    } catch (Exception unused2) {
                        c1739Nc.l("setCurrentScreen", false);
                    }
                }
            }
        }
        this.a.a(true);
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void v(BinderC1966dc binderC1966dc, String str, String str2) {
        Context context = this.b;
        C1739Nc c1739Nc = this.c;
        if (c1739Nc.e(context)) {
            try {
                c1739Nc.d(binderC1966dc.b, context, c1739Nc.a(context), this.a.c, binderC1966dc.a);
            } catch (RemoteException e) {
                com.google.android.gms.ads.internal.util.client.i.i("Remote Exception to get reward item.", e);
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.Xg
    public final void zze() {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2015ei
    public final void zzi() {
    }
}
