package io.ktor.client.call;

import io.ktor.http.A;
import io.ktor.http.k;
import io.ktor.http.p;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e implements io.ktor.client.request.b {
    public final /* synthetic */ int a = 0;
    public final /* synthetic */ io.ktor.client.request.b b;

    public e(d call, io.ktor.client.request.b origin) {
        Intrinsics.checkNotNullParameter(call, "call");
        Intrinsics.checkNotNullParameter(origin, "origin");
        this.b = origin;
    }

    @Override // io.ktor.http.o
    public final k a() {
        switch (this.a) {
        }
        return this.b.a();
    }

    @Override // io.ktor.client.request.b
    public final io.ktor.util.e f() {
        switch (this.a) {
        }
        return this.b.f();
    }

    @Override // io.ktor.client.request.b, kotlinx.coroutines.C
    public final CoroutineContext getCoroutineContext() {
        switch (this.a) {
        }
        return this.b.getCoroutineContext();
    }

    @Override // io.ktor.client.request.b
    public final A i() {
        switch (this.a) {
        }
        return this.b.i();
    }

    @Override // io.ktor.client.request.b
    public final p r() {
        switch (this.a) {
        }
        return this.b.r();
    }

    public e(io.ktor.client.plugins.observer.a call, io.ktor.client.request.b origin) {
        Intrinsics.checkNotNullParameter(call, "call");
        Intrinsics.checkNotNullParameter(origin, "origin");
        this.b = origin;
    }
}
