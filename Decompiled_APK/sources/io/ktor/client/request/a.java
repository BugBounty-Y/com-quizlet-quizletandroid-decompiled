package io.ktor.client.request;

import io.ktor.http.A;
import io.ktor.http.k;
import io.ktor.http.m;
import io.ktor.http.p;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements b {
    public final io.ktor.client.call.b a;
    public final p b;
    public final A c;
    public final m d;
    public final io.ktor.util.e e;

    public a(io.ktor.client.call.b call, d data) {
        Intrinsics.checkNotNullParameter(call, "call");
        Intrinsics.checkNotNullParameter(data, "data");
        this.a = call;
        this.b = data.b;
        this.c = data.a;
        this.d = data.c;
        this.e = data.f;
    }

    @Override // io.ktor.http.o
    public final k a() {
        return this.d;
    }

    @Override // io.ktor.client.request.b
    public final io.ktor.util.e f() {
        return this.e;
    }

    @Override // io.ktor.client.request.b, kotlinx.coroutines.C
    public final CoroutineContext getCoroutineContext() {
        return this.a.getCoroutineContext();
    }

    @Override // io.ktor.client.request.b
    public final A i() {
        return this.c;
    }

    @Override // io.ktor.client.request.b
    public final p r() {
        return this.b;
    }
}
