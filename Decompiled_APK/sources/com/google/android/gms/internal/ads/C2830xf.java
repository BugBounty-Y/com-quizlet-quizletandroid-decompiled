package com.google.android.gms.internal.ads;

import android.content.Context;
import android.net.Uri;
import android.text.TextUtils;
import android.view.MotionEvent;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.util.Random;
import java.util.concurrent.ScheduledExecutorService;

/* renamed from: com.google.android.gms.internal.ads.xf, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2830xf {
    public final Context a;
    public final com.google.android.gms.ads.internal.util.C b;
    public final C2708um c;
    public final C2535qk d;
    public final C2227jd e;
    public final Xv f;
    public final ScheduledExecutorService g;

    public C2830xf(Context context, com.google.android.gms.ads.internal.util.C c, C2708um c2708um, C2535qk c2535qk, C2227jd c2227jd, Xv xv, ScheduledExecutorService scheduledExecutorService) {
        this.a = context;
        this.b = c;
        this.c = c2708um;
        this.d = c2535qk;
        this.e = c2227jd;
        this.f = xv;
        this.g = scheduledExecutorService;
    }

    public static boolean b(String str) {
        if (TextUtils.isEmpty(str)) {
            return false;
        }
        return str.contains((CharSequence) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.ha));
    }

    public final com.google.common.util.concurrent.e a(String str, Random random) {
        return TextUtils.isEmpty(str) ? AbstractC2025es.E(str) : AbstractC2025es.A(c(str, this.d.a, random), Throwable.class, new C2260k9(this, str, 1), this.e);
    }

    public final com.google.common.util.concurrent.e c(String str, MotionEvent motionEvent, Random random) {
        Exception exc;
        com.google.common.util.concurrent.e eVarC;
        try {
            C2601s7 c2601s7 = AbstractC2773w7.ha;
            com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
            SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u7 = rVar.c;
            SharedPreferencesOnSharedPreferenceChangeListenerC2687u7 sharedPreferencesOnSharedPreferenceChangeListenerC2687u72 = rVar.c;
            try {
                if (!str.contains((CharSequence) sharedPreferencesOnSharedPreferenceChangeListenerC2687u7.a(c2601s7)) || this.b.k()) {
                    return AbstractC2025es.E(str);
                }
                Uri.Builder builderBuildUpon = Uri.parse(str).buildUpon();
                builderBuildUpon.appendQueryParameter((String) sharedPreferencesOnSharedPreferenceChangeListenerC2687u72.a(AbstractC2773w7.ia), String.valueOf(random.nextInt(SubsamplingScaleImageView.TILE_SIZE_AUTO)));
                if (motionEvent == null) {
                    try {
                        builderBuildUpon.appendQueryParameter((String) sharedPreferencesOnSharedPreferenceChangeListenerC2687u72.a(AbstractC2773w7.ja), "11");
                        return AbstractC2025es.E(builderBuildUpon.toString());
                    } catch (Exception e) {
                        exc = e;
                        return AbstractC2025es.C(exc);
                    }
                }
                C2708um c2708um = this.c;
                c2708um.getClass();
                try {
                    androidx.privacysandbox.ads.adservices.java.measurement.h hVarB = androidx.privacysandbox.ads.adservices.java.measurement.h.b(c2708um.b);
                    c2708um.a = hVarB;
                    eVarC = hVarB == null ? AbstractC2025es.C(new IllegalStateException("MeasurementManagerFutures is null")) : hVarB.c();
                } catch (Exception e2) {
                    eVarC = AbstractC2025es.C(e2);
                }
                return AbstractC2025es.A(AbstractC2025es.N(Nv.t(eVarC), new com.google.android.gms.ads.internal.c(this, builderBuildUpon, str, motionEvent, 2), this.f), Throwable.class, new C2439oa(2, this, builderBuildUpon), this.e);
            } catch (Exception e3) {
                e = e3;
                exc = e;
                return AbstractC2025es.C(exc);
            }
        } catch (Exception e4) {
            e = e4;
        }
    }
}
