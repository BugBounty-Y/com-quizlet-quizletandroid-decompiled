package com.facebook.internal;

import java.util.HashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class A {
    public static final com.google.mlkit.common.sdkinternal.model.a c = new com.google.mlkit.common.sdkinternal.model.a(8);
    public static final HashMap d = new HashMap();
    public final String a;
    public StringBuilder b;

    public A() {
        com.facebook.y behavior = com.facebook.y.a;
        Intrinsics.checkNotNullParameter(behavior, "behavior");
        Intrinsics.checkNotNullParameter("Request", "tag");
        AbstractC1554i.j("Request", "tag");
        this.a = "FacebookSDK.Request";
        this.b = new StringBuilder();
    }

    public final void a(Object value, String key) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(value, "value");
        Object[] args = {key, value};
        Intrinsics.checkNotNullParameter("  %s:\t%s\n", "format");
        Intrinsics.checkNotNullParameter(args, "args");
        c();
    }

    public final void b() {
        String string = this.b.toString();
        Intrinsics.checkNotNullExpressionValue(string, "contents.toString()");
        Intrinsics.checkNotNullParameter(string, "string");
        com.google.mlkit.common.sdkinternal.model.a.x(com.facebook.y.a, this.a, string);
        this.b = new StringBuilder();
    }

    public final void c() {
        com.facebook.o.h(com.facebook.y.a);
    }
}
