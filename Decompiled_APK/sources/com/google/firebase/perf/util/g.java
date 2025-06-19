package com.google.firebase.perf.util;

import com.google.firebase.perf.metrics.Trace;

/* loaded from: classes2.dex */
public abstract class g {
    public static final com.google.firebase.perf.logging.a a = com.google.firebase.perf.logging.a.d();

    public static void a(Trace trace, com.google.firebase.perf.metrics.c cVar) {
        int i = cVar.a;
        if (i > 0) {
            trace.putMetric("_fr_tot", i);
        }
        int i2 = cVar.b;
        if (i2 > 0) {
            trace.putMetric("_fr_slo", i2);
        }
        int i3 = cVar.c;
        if (i3 > 0) {
            trace.putMetric("_fr_fzn", i3);
        }
        String str = trace.d;
        a.a();
    }
}
