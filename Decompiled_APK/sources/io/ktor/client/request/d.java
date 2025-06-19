package io.ktor.client.request;

import io.ktor.client.plugins.X;
import io.ktor.http.A;
import io.ktor.http.m;
import io.ktor.http.p;
import java.util.Map;
import java.util.Set;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.A0;

/* loaded from: classes3.dex */
public final class d {
    public final A a;
    public final p b;
    public final m c;
    public final io.ktor.http.content.c d;
    public final A0 e;
    public final io.ktor.util.e f;
    public final Set g;

    public d(A url, p method, m headers, io.ktor.http.content.c body, A0 executionContext, io.ktor.util.e attributes) {
        Set setKeySet;
        Intrinsics.checkNotNullParameter(url, "url");
        Intrinsics.checkNotNullParameter(method, "method");
        Intrinsics.checkNotNullParameter(headers, "headers");
        Intrinsics.checkNotNullParameter(body, "body");
        Intrinsics.checkNotNullParameter(executionContext, "executionContext");
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        this.a = url;
        this.b = method;
        this.c = headers;
        this.d = body;
        this.e = executionContext;
        this.f = attributes;
        Map map = (Map) attributes.d(io.ktor.client.engine.h.a);
        this.g = (map == null || (setKeySet = map.keySet()) == null) ? M.a : setKeySet;
    }

    public final Object a() {
        X key = X.a;
        Intrinsics.checkNotNullParameter(key, "key");
        Map map = (Map) this.f.d(io.ktor.client.engine.h.a);
        if (map != null) {
            return map.get(key);
        }
        return null;
    }

    public final String toString() {
        return "HttpRequestData(url=" + this.a + ", method=" + this.b + ')';
    }
}
