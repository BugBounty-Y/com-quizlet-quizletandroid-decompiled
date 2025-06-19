package com.google.gson.internal;

import java.lang.reflect.Method;

/* loaded from: classes2.dex */
public final class q extends d {
    public final /* synthetic */ Method b;

    public q(Method method) {
        this.b = method;
    }

    @Override // com.google.gson.internal.d
    public final Object i(Class cls) {
        d.a(cls);
        return this.b.invoke(null, cls, Object.class);
    }
}
