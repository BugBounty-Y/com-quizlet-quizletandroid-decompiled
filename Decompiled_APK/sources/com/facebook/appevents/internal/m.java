package com.facebook.appevents.internal;

import android.content.Context;
import android.os.Bundle;
import androidx.room.s;
import com.facebook.B;
import com.facebook.appevents.n;
import com.facebook.appevents.p;
import com.facebook.internal.A;
import com.facebook.o;
import com.facebook.y;
import java.util.Arrays;
import java.util.Locale;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class m {
    public static final m a = new m();
    public static final long[] b = {300000, 900000, 1800000, 3600000, 21600000, 43200000, 86400000, 172800000, 259200000, 604800000, 1209600000, 1814400000, 2419200000L, 5184000000L, 7776000000L, 10368000000L, 12960000000L, 15552000000L, 31536000000L};

    public static final void b(Context context, String activityName, String str) {
        if (com.facebook.internal.instrument.crashshield.a.b(m.class)) {
            return;
        }
        try {
            Intrinsics.checkNotNullParameter(activityName, "activityName");
            Intrinsics.checkNotNullParameter(context, "context");
            Bundle bundle = new Bundle();
            bundle.putString("fb_mobile_launch_source", "Unclassified");
            Intrinsics.checkNotNullParameter(activityName, "activityName");
            Intrinsics.checkNotNullParameter(activityName, "activityName");
            com.facebook.appevents.j jVar = new com.facebook.appevents.j(activityName, str);
            new p(jVar);
            o oVar = o.a;
            if (B.c()) {
                jVar.d(bundle, "fb_mobile_activate_app");
            }
            String str2 = com.facebook.appevents.j.c;
            if (com.google.firebase.perf.logging.b.h() == 2 || com.facebook.internal.instrument.crashshield.a.b(jVar)) {
                return;
            }
            try {
                com.facebook.appevents.h.c(n.a);
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(jVar, th);
            }
        } catch (Throwable th2) {
            com.facebook.internal.instrument.crashshield.a.a(m.class, th2);
        }
    }

    public static final void d(String activityName, androidx.navigation.internal.m mVar, String str) {
        String string;
        Long l;
        if (com.facebook.internal.instrument.crashshield.a.b(m.class)) {
            return;
        }
        try {
            Intrinsics.checkNotNullParameter(activityName, "activityName");
            if (mVar == null) {
                return;
            }
            Long l2 = (Long) mVar.f;
            if (l2 == null) {
                l2 = 0L;
            }
            long jLongValue = l2.longValue();
            m mVar2 = a;
            if (jLongValue < 0) {
                mVar2.c();
                jLongValue = 0;
            }
            Long l3 = (Long) mVar.d;
            long jLongValue2 = (l3 == null || (l = (Long) mVar.b) == null) ? 0L : l.longValue() - l3.longValue();
            if (jLongValue2 < 0) {
                mVar2.c();
                jLongValue2 = 0;
            }
            Bundle bundle = new Bundle();
            bundle.putInt("fb_mobile_app_interruptions", mVar.c);
            Locale locale = Locale.ROOT;
            int i = 0;
            if (!com.facebook.internal.instrument.crashshield.a.b(m.class)) {
                int i2 = 0;
                while (true) {
                    try {
                        long[] jArr = b;
                        if (i2 >= 19 || jArr[i2] >= jLongValue) {
                            break;
                        } else {
                            i2++;
                        }
                    } catch (Throwable th) {
                        com.facebook.internal.instrument.crashshield.a.a(m.class, th);
                    }
                }
                i = i2;
            }
            String str2 = String.format(locale, "session_quanta_%d", Arrays.copyOf(new Object[]{Integer.valueOf(i)}, 1));
            Intrinsics.checkNotNullExpressionValue(str2, "format(locale, format, *args)");
            bundle.putString("fb_mobile_time_between_sessions", str2);
            s sVar = (s) mVar.g;
            if (sVar == null || (string = sVar.toString()) == null) {
                string = "Unclassified";
            }
            bundle.putString("fb_mobile_launch_source", string);
            Long l4 = (Long) mVar.b;
            bundle.putLong("_logTime", (l4 != null ? l4.longValue() : 0L) / 1000);
            Intrinsics.checkNotNullParameter(activityName, "activityName");
            Intrinsics.checkNotNullParameter(activityName, "activityName");
            new p(new com.facebook.appevents.j(activityName, str)).a("fb_mobile_deactivate_app", jLongValue2 / 1000, bundle);
        } catch (Throwable th2) {
            com.facebook.internal.instrument.crashshield.a.a(m.class, th2);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:23:0x0032 A[Catch: all -> 0x0048, TRY_LEAVE, TryCatch #1 {, blocks: (B:11:0x0016, B:15:0x0020, B:23:0x0032, B:29:0x0044, B:21:0x002d, B:26:0x0040, B:18:0x0029), top: B:40:0x0016, inners: #0, #2 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.facebook.appevents.internal.h a() {
        /*
            r3 = this;
            java.lang.Class<com.facebook.appevents.internal.h> r0 = com.facebook.appevents.internal.h.class
            boolean r1 = com.facebook.internal.instrument.crashshield.a.b(r0)
            r2 = 0
            if (r1 == 0) goto Lb
        L9:
            r0 = r2
            goto L13
        Lb:
            com.facebook.appevents.internal.h r0 = com.facebook.appevents.internal.h.c     // Catch: java.lang.Throwable -> Le
            goto L13
        Le:
            r1 = move-exception
            com.facebook.internal.instrument.crashshield.a.a(r0, r1)
            goto L9
        L13:
            if (r0 != 0) goto L4e
            monitor-enter(r3)
            java.util.concurrent.atomic.AtomicBoolean r0 = com.facebook.o.o     // Catch: java.lang.Throwable -> L48
            boolean r0 = r0.get()     // Catch: java.lang.Throwable -> L48
            if (r0 != 0) goto L20
            monitor-exit(r3)
            return r2
        L20:
            java.lang.Class<com.facebook.appevents.internal.h> r0 = com.facebook.appevents.internal.h.class
            boolean r1 = com.facebook.internal.instrument.crashshield.a.b(r0)     // Catch: java.lang.Throwable -> L48
            if (r1 == 0) goto L29
            goto L30
        L29:
            com.facebook.appevents.internal.h r2 = com.facebook.appevents.internal.h.c     // Catch: java.lang.Throwable -> L2c
            goto L30
        L2c:
            r1 = move-exception
            com.facebook.internal.instrument.crashshield.a.a(r0, r1)     // Catch: java.lang.Throwable -> L48
        L30:
            if (r2 != 0) goto L4a
            com.facebook.appevents.internal.h r2 = new com.facebook.appevents.internal.h     // Catch: java.lang.Throwable -> L48
            r2.<init>()     // Catch: java.lang.Throwable -> L48
            java.lang.Class<com.facebook.appevents.internal.h> r0 = com.facebook.appevents.internal.h.class
            boolean r1 = com.facebook.internal.instrument.crashshield.a.b(r0)     // Catch: java.lang.Throwable -> L48
            if (r1 == 0) goto L40
            goto L4a
        L40:
            com.facebook.appevents.internal.h.c = r2     // Catch: java.lang.Throwable -> L43
            goto L4a
        L43:
            r1 = move-exception
            com.facebook.internal.instrument.crashshield.a.a(r0, r1)     // Catch: java.lang.Throwable -> L48
            goto L4a
        L48:
            r0 = move-exception
            goto L4c
        L4a:
            monitor-exit(r3)
            return r2
        L4c:
            monitor-exit(r3)
            throw r0
        L4e:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.internal.m.a():com.facebook.appevents.internal.h");
    }

    public void c() {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            com.google.mlkit.common.sdkinternal.model.a aVar = A.c;
            com.google.mlkit.common.sdkinternal.model.a.v(y.d, "com.facebook.appevents.internal.m", "Clock skew detected");
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }
}
