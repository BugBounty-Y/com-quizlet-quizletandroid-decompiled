package com.snowplowanalytics.core.emitter;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3397u1;
import java.util.EnumSet;
import java.util.concurrent.TimeUnit;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class b {
    public static final EnumSet a;
    public static final int b;
    public static final int c;
    public static final int d;
    public static final long e;
    public static final long f;
    public static final int g;
    public static final int h;
    public static final boolean i;
    public static final TimeUnit j;
    public static final long k;
    public static final long l;

    static {
        EnumSet enumSetOf = EnumSet.of(d.a);
        Intrinsics.checkNotNullExpressionValue(enumSetOf, "of(TLSVersion.TLSv1_2)");
        a = enumSetOf;
        b = 25;
        c = 5;
        d = 5;
        e = 40000L;
        f = 40000L;
        g = 30;
        h = 15;
        i = true;
        j = TimeUnit.SECONDS;
        k = AbstractC3397u1.f(30, kotlin.time.d.g);
        l = 1000L;
    }
}
