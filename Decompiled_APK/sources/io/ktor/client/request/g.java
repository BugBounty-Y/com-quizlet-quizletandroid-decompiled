package io.ktor.client.request;

import io.ktor.http.q;
import io.ktor.http.r;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g {
    public final r a;
    public final io.ktor.util.date.d b;
    public final io.ktor.client.engine.okhttp.h c;
    public final q d;
    public final Object e;
    public final CoroutineContext f;
    public final io.ktor.util.date.d g;

    public g(r statusCode, io.ktor.util.date.d requestTime, io.ktor.client.engine.okhttp.h headers, q version, Object body, CoroutineContext callContext) {
        Intrinsics.checkNotNullParameter(statusCode, "statusCode");
        Intrinsics.checkNotNullParameter(requestTime, "requestTime");
        Intrinsics.checkNotNullParameter(headers, "headers");
        Intrinsics.checkNotNullParameter(version, "version");
        Intrinsics.checkNotNullParameter(body, "body");
        Intrinsics.checkNotNullParameter(callContext, "callContext");
        this.a = statusCode;
        this.b = requestTime;
        this.c = headers;
        this.d = version;
        this.e = body;
        this.f = callContext;
        this.g = io.ktor.util.date.a.a(null);
    }

    public final String toString() {
        return "HttpResponseData=(statusCode=" + this.a + ')';
    }
}
