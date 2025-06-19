package com.facebook.appevents.codeless;

import android.hardware.SensorManager;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class d {
    public static SensorManager c;
    public static k d;
    public static String e;
    public static volatile boolean h;
    public static final d a = new d();
    public static final l b = new l();
    public static final AtomicBoolean f = new AtomicBoolean(true);
    public static final AtomicBoolean g = new AtomicBoolean(false);

    public static final String a() {
        if (com.facebook.internal.instrument.crashshield.a.b(d.class)) {
            return null;
        }
        try {
            if (e == null) {
                e = UUID.randomUUID().toString();
            }
            String str = e;
            Intrinsics.e(str, "null cannot be cast to non-null type kotlin.String");
            return str;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(d.class, th);
            return null;
        }
    }
}
