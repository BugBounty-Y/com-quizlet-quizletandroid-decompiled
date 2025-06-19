package com.google.android.gms.internal.ads;

import java.util.NoSuchElementException;

/* renamed from: com.google.android.gms.internal.ads.ru, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2587ru extends Pu {
    public final Object b;
    public boolean c;

    public C2587ru(Object obj) {
        super(0);
        this.b = obj;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        return !this.c;
    }

    @Override // com.google.android.gms.internal.ads.Pu, java.util.Iterator
    public final Object next() {
        if (this.c) {
            throw new NoSuchElementException();
        }
        this.c = true;
        return this.b;
    }
}
