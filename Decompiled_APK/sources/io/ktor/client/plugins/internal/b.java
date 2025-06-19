package io.ktor.client.plugins.internal;

import io.ktor.utils.io.A;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.r;

/* loaded from: classes3.dex */
public final class b {
    public final r a;
    public A b;
    public final /* synthetic */ d c;

    public b(d dVar) {
        r savedResponse = E.b();
        Intrinsics.checkNotNullParameter(savedResponse, "savedResponse");
        this.c = dVar;
        this.a = savedResponse;
    }
}
