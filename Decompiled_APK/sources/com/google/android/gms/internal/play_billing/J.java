package com.google.android.gms.internal.play_billing;

import java.util.NoSuchElementException;

/* loaded from: classes2.dex */
public final class J extends AbstractC3783b0 {
    public final Object a;
    public boolean b;

    public J(Object obj) {
        this.a = obj;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        return !this.b;
    }

    @Override // java.util.Iterator
    public final Object next() {
        if (this.b) {
            throw new NoSuchElementException();
        }
        this.b = true;
        return this.a;
    }
}
