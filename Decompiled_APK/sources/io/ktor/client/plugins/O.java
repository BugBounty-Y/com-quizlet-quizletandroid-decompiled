package io.ktor.client.plugins;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class O {
    public final io.ktor.client.request.c a;
    public final io.ktor.client.statement.b b;

    public O(io.ktor.client.request.c request, int i, io.ktor.client.statement.b bVar, Throwable th) {
        Intrinsics.checkNotNullParameter(request, "request");
        this.a = request;
        this.b = bVar;
    }
}
