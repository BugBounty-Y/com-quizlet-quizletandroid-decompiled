package com.facebook.appevents;

import android.content.Context;
import android.os.Bundle;
import com.facebook.AccessToken;
import com.facebook.internal.A;
import com.facebook.internal.AbstractC1554i;
import com.facebook.internal.J;
import com.facebook.y;
import com.google.android.gms.internal.mlkit_vision_common.D;
import java.math.BigDecimal;
import java.util.Currency;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class j {
    public static final String c;
    public static ScheduledThreadPoolExecutor d;
    public static final Object e;
    public static String f;
    public static boolean g;
    public final String a;
    public final b b;

    static {
        String canonicalName = j.class.getCanonicalName();
        if (canonicalName == null) {
            canonicalName = "com.facebook.appevents.AppEventsLoggerImpl";
        }
        c = canonicalName;
        e = new Object();
    }

    public j(String activityName, String str) {
        Intrinsics.checkNotNullParameter(activityName, "activityName");
        AbstractC1554i.k();
        this.a = activityName;
        Date date = AccessToken.l;
        AccessToken accessToken = D.c();
        if (accessToken == null || new Date().after(accessToken.a) || !(str == null || str.equals(accessToken.h))) {
            this.b = new b(null, str == null ? J.t(com.facebook.o.a()) : str);
        } else {
            Intrinsics.checkNotNullParameter(accessToken, "accessToken");
            this.b = new b(accessToken.e, com.facebook.o.b());
        }
        com.google.firebase.perf.logging.b.j();
    }

    public static final /* synthetic */ String a() {
        if (com.facebook.internal.instrument.crashshield.a.b(j.class)) {
            return null;
        }
        try {
            return f;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(j.class, th);
            return null;
        }
    }

    public static final /* synthetic */ ScheduledThreadPoolExecutor b() {
        if (com.facebook.internal.instrument.crashshield.a.b(j.class)) {
            return null;
        }
        try {
            return d;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(j.class, th);
            return null;
        }
    }

    public static final /* synthetic */ Object c() {
        if (com.facebook.internal.instrument.crashshield.a.b(j.class)) {
            return null;
        }
        try {
            return e;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(j.class, th);
            return null;
        }
    }

    public static /* synthetic */ void f(j jVar, String str, Double d2, Bundle bundle, boolean z, UUID uuid) {
        if (com.facebook.internal.instrument.crashshield.a.b(j.class)) {
            return;
        }
        try {
            jVar.e(str, d2, bundle, z, uuid, null);
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(j.class, th);
        }
    }

    public final void d(Bundle bundle, String str) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            try {
                f(this, str, null, bundle, false, com.facebook.appevents.internal.c.b());
            } catch (Throwable th) {
                th = th;
                com.facebook.internal.instrument.crashshield.a.a(this, th);
            }
        } catch (Throwable th2) {
            th = th2;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:78:0x0119  */
    /* JADX WARN: Type inference failed for: r1v10 */
    /* JADX WARN: Type inference failed for: r1v11, types: [java.util.Currency] */
    /* JADX WARN: Type inference failed for: r1v17, types: [java.util.Currency] */
    /* JADX WARN: Type inference failed for: r1v9 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void e(java.lang.String r12, java.lang.Double r13, android.os.Bundle r14, boolean r15, java.util.UUID r16, com.facebook.appevents.q r17) {
        /*
            Method dump skipped, instructions count: 453
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.j.e(java.lang.String, java.lang.Double, android.os.Bundle, boolean, java.util.UUID, com.facebook.appevents.q):void");
    }

    public final void g(Bundle bundle, String str) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            try {
                f(this, str, null, bundle, true, com.facebook.appevents.internal.c.b());
            } catch (Throwable th) {
                th = th;
                com.facebook.internal.instrument.crashshield.a.a(this, th);
            }
        } catch (Throwable th2) {
            th = th2;
        }
    }

    public final void h(BigDecimal bigDecimal, Currency currency, Bundle bundle, q qVar) {
        Throwable th;
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        if (currency == null) {
            try {
                com.google.mlkit.common.sdkinternal.model.a aVar = A.c;
                com.google.mlkit.common.sdkinternal.model.a.v(y.e, "AppEvents", "currency cannot be null");
                return;
            } catch (Throwable th2) {
                th = th2;
            }
        } else {
            try {
                bundle.putString("fb_currency", currency.getCurrencyCode());
                try {
                    e("fb_mobile_purchase", Double.valueOf(bigDecimal.doubleValue()), bundle, true, com.facebook.appevents.internal.c.b(), qVar);
                    if (com.google.firebase.perf.logging.b.h() != 2) {
                        h.c(n.d);
                        return;
                    }
                    return;
                } catch (Throwable th3) {
                    th = th3;
                    th = th;
                    com.facebook.internal.instrument.crashshield.a.a(this, th);
                }
            } catch (Throwable th4) {
                th = th4;
            }
        }
        com.facebook.internal.instrument.crashshield.a.a(this, th);
    }

    public j(Context context, String str) {
        this(J.l(context), str);
    }
}
