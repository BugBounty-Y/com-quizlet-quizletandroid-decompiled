package io.ktor.client.plugins.api;

import java.io.Closeable;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e implements Closeable, AutoCloseable {
    public final io.ktor.util.a a;
    public final Object b;
    public final Function1 c;
    public Function0 d;

    public e(io.ktor.util.a key, Object config, Function1 body) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(config, "config");
        Intrinsics.checkNotNullParameter(body, "body");
        this.a = key;
        this.b = config;
        this.c = body;
        this.d = new b(1);
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
        this.d.invoke();
    }
}
