package com.google.common.cache;

import java.lang.ref.ReferenceQueue;

/* loaded from: classes2.dex */
public class B implements C {
    public final Object a;

    public B(Object obj) {
        this.a = obj;
    }

    @Override // com.google.common.cache.C
    public final boolean a() {
        return true;
    }

    @Override // com.google.common.cache.C
    public final void b(Object obj) {
    }

    @Override // com.google.common.cache.C
    public int c() {
        return 1;
    }

    @Override // com.google.common.cache.C
    public final boolean d() {
        return false;
    }

    @Override // com.google.common.cache.C
    public final C e(ReferenceQueue referenceQueue, Object obj, J j) {
        return this;
    }

    @Override // com.google.common.cache.C
    public final J f() {
        return null;
    }

    @Override // com.google.common.cache.C
    public final Object get() {
        return this.a;
    }
}
