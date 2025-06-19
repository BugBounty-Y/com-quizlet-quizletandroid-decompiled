package com.google.android.gms.internal.ads;

import java.util.NoSuchElementException;

/* renamed from: com.google.android.gms.internal.ads.xA, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2819xA extends Pu {
    public int b;
    public final int c;
    public final /* synthetic */ BA d;

    public C2819xA(BA ba) {
        super(1);
        this.d = ba;
        this.b = 0;
        this.c = ba.g();
    }

    @Override // com.google.android.gms.internal.ads.Pu
    public final byte a() {
        int i = this.b;
        if (i >= this.c) {
            throw new NoSuchElementException();
        }
        this.b = i + 1;
        return this.d.c(i);
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        return this.b < this.c;
    }
}
