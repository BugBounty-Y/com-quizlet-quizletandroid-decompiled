package com.squareup.moshi;

import java.lang.reflect.Method;

/* renamed from: com.squareup.moshi.c, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4848c extends H {
    public final /* synthetic */ Method k;
    public final /* synthetic */ Object l;
    public final /* synthetic */ Class m;

    public C4848c(Method method, Object obj, Class cls) {
        this.k = method;
        this.l = obj;
        this.m = cls;
    }

    @Override // com.squareup.moshi.H
    public final Object e() {
        return this.k.invoke(this.l, this.m);
    }

    public final String toString() {
        return this.m.getName();
    }
}
