package com.google.gson.internal;

import java.lang.reflect.Method;

/* loaded from: classes2.dex */
public final class p extends d {
    public final /* synthetic */ Method b;
    public final /* synthetic */ int c;

    public p(Method method, int i) {
        this.b = method;
        this.c = i;
    }

    @Override // com.google.gson.internal.d
    public final Object i(Class cls) {
        d.a(cls);
        return this.b.invoke(null, cls, Integer.valueOf(this.c));
    }
}
