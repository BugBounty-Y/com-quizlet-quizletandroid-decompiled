package com.facebook.appevents.gps.topics;

import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;

/* loaded from: classes.dex */
public abstract class b {
    public static final AtomicBoolean a;

    static {
        Intrinsics.checkNotNullExpressionValue(b.class.toString(), "GpsTopicsManager::class.java.toString()");
        l.b(a.a);
        a = new AtomicBoolean(false);
    }
}
