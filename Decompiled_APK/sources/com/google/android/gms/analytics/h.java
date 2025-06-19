package com.google.android.gms.analytics;

import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes2.dex */
public final class h implements ThreadFactory {
    public static final AtomicInteger a = new AtomicInteger();

    @Override // java.util.concurrent.ThreadFactory
    public final Thread newThread(Runnable runnable) {
        return new i(runnable, android.support.v4.media.session.a.f(a.incrementAndGet(), "measurement-"));
    }
}
