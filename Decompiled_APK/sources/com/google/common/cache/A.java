package com.google.common.cache;

/* loaded from: classes2.dex */
public class A extends AbstractC3915i {
    public final Object a;
    public final int b;
    public final J c;
    public volatile C d = I.v;

    public A(Object obj, int i, J j) {
        this.a = obj;
        this.b = i;
        this.c = j;
    }

    @Override // com.google.common.cache.AbstractC3915i, com.google.common.cache.J
    public final void b(C c) {
        this.d = c;
    }

    @Override // com.google.common.cache.AbstractC3915i, com.google.common.cache.J
    public final Object getKey() {
        return this.a;
    }

    @Override // com.google.common.cache.AbstractC3915i, com.google.common.cache.J
    public final J getNext() {
        return this.c;
    }

    @Override // com.google.common.cache.AbstractC3915i, com.google.common.cache.J
    public final C h() {
        return this.d;
    }

    @Override // com.google.common.cache.AbstractC3915i, com.google.common.cache.J
    public final int p() {
        return this.b;
    }
}
