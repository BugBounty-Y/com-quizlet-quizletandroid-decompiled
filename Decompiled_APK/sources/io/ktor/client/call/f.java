package io.ktor.client.call;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3216n7;
import io.ktor.client.engine.okhttp.h;
import io.ktor.client.request.g;
import io.ktor.http.k;
import io.ktor.http.q;
import io.ktor.http.r;
import io.ktor.utils.io.m;
import io.ktor.utils.io.n;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f extends io.ktor.client.statement.b {
    public final /* synthetic */ int a = 1;
    public final CoroutineContext b;
    public final r c;
    public final q d;
    public final io.ktor.util.date.d e;
    public final io.ktor.util.date.d f;
    public final b g;
    public final Object h;
    public final k i;

    public f(b call, g responseData) {
        Intrinsics.checkNotNullParameter(call, "call");
        Intrinsics.checkNotNullParameter(responseData, "responseData");
        this.g = call;
        this.b = responseData.f;
        this.c = responseData.a;
        this.d = responseData.d;
        this.e = responseData.b;
        this.f = responseData.g;
        Object obj = responseData.e;
        n nVar = obj instanceof n ? (n) obj : null;
        if (nVar == null) {
            n.a.getClass();
            nVar = m.b;
        }
        this.h = nVar;
        this.i = responseData.c;
    }

    @Override // io.ktor.http.o
    public final k a() {
        switch (this.a) {
            case 0:
                return this.i;
            default:
                return (h) this.i;
        }
    }

    @Override // io.ktor.client.statement.b
    public final b b() {
        switch (this.a) {
            case 0:
                return (d) this.g;
            default:
                return this.g;
        }
    }

    @Override // io.ktor.client.statement.b
    public final n c() {
        switch (this.a) {
            case 0:
                return AbstractC3216n7.a((byte[]) this.h);
            default:
                return (n) this.h;
        }
    }

    @Override // io.ktor.client.statement.b
    public final io.ktor.util.date.d d() {
        switch (this.a) {
        }
        return this.e;
    }

    @Override // io.ktor.client.statement.b
    public final io.ktor.util.date.d e() {
        switch (this.a) {
        }
        return this.f;
    }

    @Override // io.ktor.client.statement.b
    public final r g() {
        switch (this.a) {
        }
        return this.c;
    }

    @Override // kotlinx.coroutines.C
    public final CoroutineContext getCoroutineContext() {
        switch (this.a) {
        }
        return this.b;
    }

    @Override // io.ktor.client.statement.b
    public final q h() {
        switch (this.a) {
        }
        return this.d;
    }

    public f(d call, byte[] body, io.ktor.client.statement.b origin) {
        Intrinsics.checkNotNullParameter(call, "call");
        Intrinsics.checkNotNullParameter(body, "body");
        Intrinsics.checkNotNullParameter(origin, "origin");
        this.g = call;
        this.h = body;
        this.c = origin.g();
        this.d = origin.h();
        this.e = origin.d();
        this.f = origin.e();
        this.i = origin.a();
        this.b = origin.getCoroutineContext();
    }
}
