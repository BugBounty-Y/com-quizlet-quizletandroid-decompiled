package io.ktor.client.plugins;

import java.util.Map;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: io.ktor.client.plugins.t, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4872t implements io.ktor.client.request.b {
    public final io.ktor.http.p a;
    public final io.ktor.http.A b;
    public final io.ktor.util.e c;
    public final io.ktor.http.m d;

    public C4872t(io.ktor.client.request.c cVar) {
        this.a = cVar.b;
        this.b = cVar.a.b();
        this.c = cVar.f;
        Map values = (Map) cVar.c.b;
        Intrinsics.checkNotNullParameter(values, "values");
        this.d = new io.ktor.http.m(values);
    }

    @Override // io.ktor.http.o
    public final io.ktor.http.k a() {
        return this.d;
    }

    @Override // io.ktor.client.request.b
    public final io.ktor.util.e f() {
        return this.c;
    }

    @Override // io.ktor.client.request.b, kotlinx.coroutines.C
    public final CoroutineContext getCoroutineContext() {
        throw new IllegalStateException("Call is not initialized");
    }

    @Override // io.ktor.client.request.b
    public final io.ktor.http.A i() {
        return this.b;
    }

    @Override // io.ktor.client.request.b
    public final io.ktor.http.p r() {
        return this.a;
    }
}
