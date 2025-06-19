package com.facebook.appevents.ondeviceprocessing;

import java.util.Set;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a {
    public static final a a = new a();
    public static final Set b;

    static {
        String[] elements = {"fb_mobile_purchase", "StartTrial", "Subscribe"};
        Intrinsics.checkNotNullParameter(elements, "elements");
        b = C4933y.T(elements);
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x0025  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final boolean a() {
        /*
            com.facebook.appevents.ondeviceprocessing.e r0 = com.facebook.appevents.ondeviceprocessing.e.a
            java.lang.Class<com.facebook.appevents.ondeviceprocessing.a> r1 = com.facebook.appevents.ondeviceprocessing.a.class
            boolean r2 = com.facebook.internal.instrument.crashshield.a.b(r1)
            r3 = 0
            if (r2 == 0) goto Lc
            return r3
        Lc:
            android.content.Context r2 = com.facebook.o.a()     // Catch: java.lang.Throwable -> L52
            boolean r2 = com.facebook.o.f(r2)     // Catch: java.lang.Throwable -> L52
            if (r2 != 0) goto L54
            boolean r2 = com.facebook.internal.J.B()     // Catch: java.lang.Throwable -> L52
            if (r2 != 0) goto L54
            java.lang.Class<com.facebook.appevents.ondeviceprocessing.e> r2 = com.facebook.appevents.ondeviceprocessing.e.class
            boolean r4 = com.facebook.internal.instrument.crashshield.a.b(r2)     // Catch: java.lang.Throwable -> L52
            r5 = 1
            if (r4 == 0) goto L27
        L25:
            r0 = r3
            goto L4e
        L27:
            java.lang.Boolean r4 = com.facebook.appevents.ondeviceprocessing.e.b     // Catch: java.lang.Throwable -> L3f
            if (r4 != 0) goto L41
            android.content.Context r4 = com.facebook.o.a()     // Catch: java.lang.Throwable -> L3f
            android.content.Intent r0 = r0.a(r4)     // Catch: java.lang.Throwable -> L3f
            if (r0 == 0) goto L37
            r0 = r5
            goto L38
        L37:
            r0 = r3
        L38:
            java.lang.Boolean r0 = java.lang.Boolean.valueOf(r0)     // Catch: java.lang.Throwable -> L3f
            com.facebook.appevents.ondeviceprocessing.e.b = r0     // Catch: java.lang.Throwable -> L3f
            goto L41
        L3f:
            r0 = move-exception
            goto L4a
        L41:
            java.lang.Boolean r0 = com.facebook.appevents.ondeviceprocessing.e.b     // Catch: java.lang.Throwable -> L3f
            if (r0 == 0) goto L25
            boolean r0 = r0.booleanValue()     // Catch: java.lang.Throwable -> L3f
            goto L4e
        L4a:
            com.facebook.internal.instrument.crashshield.a.a(r2, r0)     // Catch: java.lang.Throwable -> L52
            goto L25
        L4e:
            if (r0 == 0) goto L54
            r3 = r5
            goto L54
        L52:
            r0 = move-exception
            goto L55
        L54:
            return r3
        L55:
            com.facebook.internal.instrument.crashshield.a.a(r1, r0)
            return r3
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.ondeviceprocessing.a.a():boolean");
    }
}
