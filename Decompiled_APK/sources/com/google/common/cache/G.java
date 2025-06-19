package com.google.common.cache;

import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;

/* loaded from: classes2.dex */
public class G extends WeakReference implements C {
    public final J a;

    public G(ReferenceQueue referenceQueue, Object obj, J j) {
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
        return new G(referenceQueue, obj, j);
    }

    @Override // com.google.common.cache.C
    public final J f() {
        return this.a;
    }
}
