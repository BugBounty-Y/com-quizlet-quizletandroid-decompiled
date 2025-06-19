package com.google.gson.internal;

import java.lang.reflect.Method;

/* loaded from: classes2.dex */
public final class o extends d {
    public final /* synthetic */ Method b;
    public final /* synthetic */ Object c;

    public o(Object obj, Method method) {
        this.b = method;
        this.c = obj;
    }

    @Override // com.google.gson.internal.d
    public final Object i(Class cls) {
        d.a(cls);
        return this.b.invoke(this.c, cls);
    }
}
