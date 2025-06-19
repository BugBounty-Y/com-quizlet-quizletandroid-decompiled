package io.ktor.client.plugins;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class N {
    public final io.ktor.client.request.c a;
    public final io.ktor.client.statement.b b;

    public N(io.ktor.client.request.c request, io.ktor.client.statement.b bVar) {
        Intrinsics.checkNotNullParameter(request, "request");
        this.a = request;
        this.b = bVar;
    }
}
