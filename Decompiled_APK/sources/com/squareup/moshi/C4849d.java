package com.squareup.moshi;

import java.lang.reflect.Method;

/* renamed from: com.squareup.moshi.d, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4849d extends H {
    public final /* synthetic */ Method k;
    public final /* synthetic */ Class l;
    public final /* synthetic */ int m;

    public C4849d(Method method, Class cls, int i) {
        this.k = method;
        this.l = cls;
        this.m = i;
    }

    @Override // com.squareup.moshi.H
    public final Object e() {
        return this.k.invoke(null, this.l, Integer.valueOf(this.m));
    }

    public final String toString() {
        return this.l.getName();
    }
}
