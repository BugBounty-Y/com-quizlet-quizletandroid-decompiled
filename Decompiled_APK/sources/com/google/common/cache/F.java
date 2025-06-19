package com.google.common.cache;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;

/* loaded from: classes2.dex */
public class F extends WeakReference implements J {
    public final int a;
    public final J b;
    public volatile C c;

    public F(ReferenceQueue referenceQueue, Object obj, int i, J j) {
        super(obj, referenceQueue);
        this.c = I.v;
        this.a = i;
        this.b = j;
    }

    public J a() {
        throw new UnsupportedOperationException();
    }

    @Override // com.google.common.cache.J
    public final void b(C c) {
        this.c = c;
    }

    public long c() {
        throw new UnsupportedOperationException();
    }

    public void d(long j) {
        throw new UnsupportedOperationException();
    }

    public J e() {
        throw new UnsupportedOperationException();
    }

    public long f() {
        throw new UnsupportedOperationException();
    }

    public void g(long j) {
        throw new UnsupportedOperationException();
    }

    @Override // com.google.common.cache.J
    public final Object getKey() {
        return get();
    }

    @Override // com.google.common.cache.J
    public final J getNext() {
        return this.b;
    }

    @Override // com.google.common.cache.J
    public final C h() {
        return this.c;
    }

    public J j() {
        throw new UnsupportedOperationException();
    }

    public void k(J j) {
        throw new UnsupportedOperationException();
    }

    public void l(J j) {
        throw new UnsupportedOperationException();
    }

    public void m(J j) {
        throw new UnsupportedOperationException();
    }

    public void n(J j) {
        throw new UnsupportedOperationException();
    }

    public J o() {
        throw new UnsupportedOperationException();
    }

    @Override // com.google.common.cache.J
    public final int p() {
        return this.a;
    }
}
