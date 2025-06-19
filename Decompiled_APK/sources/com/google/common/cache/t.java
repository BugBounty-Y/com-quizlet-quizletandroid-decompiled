package com.google.common.cache;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.SoftReference;

/* loaded from: classes2.dex */
public class t extends SoftReference implements C {
    public final J a;

    public t(ReferenceQueue referenceQueue, Object obj, J j) {
        super(obj, referenceQueue);
        this.a = j;
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
    public C e(ReferenceQueue referenceQueue, Object obj, J j) {
        return new t(referenceQueue, obj, j);
    }

    @Override // com.google.common.cache.C
    public final J f() {
        return this.a;
    }
}
