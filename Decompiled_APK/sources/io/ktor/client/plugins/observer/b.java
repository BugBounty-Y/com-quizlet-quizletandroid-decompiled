package io.ktor.client.plugins.observer;

import io.ktor.http.k;
import io.ktor.http.q;
import io.ktor.http.r;
import io.ktor.util.date.d;
import io.ktor.utils.io.n;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends io.ktor.client.statement.b {
    public final a a;
    public final Function0 b;
    public final io.ktor.client.statement.b c;
    public final k d;
    public final CoroutineContext e;

    public b(a call, Function0 block, io.ktor.client.statement.b origin, k headers) {
        Intrinsics.checkNotNullParameter(call, "call");
        Intrinsics.checkNotNullParameter(block, "block");
        Intrinsics.checkNotNullParameter(origin, "origin");
        Intrinsics.checkNotNullParameter(headers, "headers");
        this.a = call;
        this.b = block;
        this.c = origin;
        this.d = headers;
        this.e = origin.getCoroutineContext();
    }

    @Override // io.ktor.http.o
    public final k a() {
        return this.d;
    }

    @Override // io.ktor.client.statement.b
    public final io.ktor.client.call.b b() {
        return this.a;
    }

    @Override // io.ktor.client.statement.b
    public final n c() {
        return (n) this.b.invoke();
    }

    @Override // io.ktor.client.statement.b
    public final d d() {
        return this.c.d();
    }

    @Override // io.ktor.client.statement.b
    public final d e() {
        return this.c.e();
    }

    @Override // io.ktor.client.statement.b
    public final r g() {
        return this.c.g();
    }

    @Override // kotlinx.coroutines.C
    public final CoroutineContext getCoroutineContext() {
        return this.e;
    }

    @Override // io.ktor.client.statement.b
    public final q h() {
        return this.c.h();
    }
}
