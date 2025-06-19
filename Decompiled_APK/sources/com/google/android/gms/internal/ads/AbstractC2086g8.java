package com.google.android.gms.internal.ads;

import com.davemorrissey.labs.subscaleview.BuildConfig;

/* renamed from: com.google.android.gms.internal.ads.g8, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2086g8 {
    public static final I3 a = I3.h(10000, "gads:dynamite_load:fail:sample_rate");
    public static final I3 b = I3.n("gads:report_dynamite_crash_in_background_thread", false);
    public static final I3 c = new I3("gads:public_beta:traffic_multiplier", 4, BuildConfig.VERSION_NAME);
    public static final I3 d = new I3("gads:sdk_crash_report_class_prefix", 4, "com.google.");
    public static final I3 e = I3.n("gads:sdk_crash_report_full_stacktrace", false);
    public static final I3 f = new I3("gads:trapped_exception_sample_rate", 3, Double.valueOf(0.01d));
}
