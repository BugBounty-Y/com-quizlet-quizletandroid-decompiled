package com.bumptech.glide.load.engine.executor;

import androidx.camera.core.impl.utils.futures.h;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes.dex */
public final class c implements ThreadFactory {
    public final b a;
    public final String b;
    public final d c;
    public final boolean d;
    public final AtomicInteger e;

    public c(b bVar, String str, boolean z) {
        d dVar = d.a;
        this.e = new AtomicInteger();
        this.a = bVar;
        this.b = str;
        this.c = dVar;
        this.d = z;
    }

    @Override // java.util.concurrent.ThreadFactory
    public final Thread newThread(Runnable runnable) {
        h hVar = new h(this, false, runnable, 12);
        this.a.getClass();
        a aVar = new a(hVar);
        aVar.setName("glide-" + this.b + "-thread-" + this.e.getAndIncrement());
        return aVar;
    }
}
