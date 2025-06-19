package com.google.common.cache;

import java.util.AbstractQueue;

/* renamed from: com.google.common.cache.k, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3917k extends com.google.android.gms.internal.common.g {
    public Object b;
    public final /* synthetic */ int c;
    public final /* synthetic */ AbstractQueue d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C3917k(AbstractQueue abstractQueue, J j, int i) {
        super(5);
        this.c = i;
        this.d = abstractQueue;
        this.b = j;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        return this.b != null;
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x001a  */
    @Override // java.util.Iterator
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object next() {
        /*
            r3 = this;
            java.lang.Object r0 = r3.b
            if (r0 == 0) goto L31
            int r1 = r3.c
            switch(r1) {
                case 0: goto L1c;
                default: goto L9;
            }
        L9:
            r1 = r0
            com.google.common.cache.J r1 = (com.google.common.cache.J) r1
            com.google.common.cache.J r1 = r1.e()
            java.util.AbstractQueue r2 = r3.d
            com.google.common.cache.l r2 = (com.google.common.cache.l) r2
            com.google.common.cache.i r2 = r2.b
            com.google.common.cache.j r2 = (com.google.common.cache.C3916j) r2
            if (r1 != r2) goto L2e
        L1a:
            r1 = 0
            goto L2e
        L1c:
            r1 = r0
            com.google.common.cache.J r1 = (com.google.common.cache.J) r1
            com.google.common.cache.J r1 = r1.j()
            java.util.AbstractQueue r2 = r3.d
            com.google.common.cache.l r2 = (com.google.common.cache.l) r2
            com.google.common.cache.i r2 = r2.b
            com.google.common.cache.j r2 = (com.google.common.cache.C3916j) r2
            if (r1 != r2) goto L2e
            goto L1a
        L2e:
            r3.b = r1
            return r0
        L31:
            java.util.NoSuchElementException r0 = new java.util.NoSuchElementException
            r0.<init>()
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.common.cache.C3917k.next():java.lang.Object");
    }
}
