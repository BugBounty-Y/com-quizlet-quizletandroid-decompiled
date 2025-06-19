package com.google.android.gms.internal.fido;

import java.util.NoSuchElementException;

/* renamed from: com.google.android.gms.internal.fido.t, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2955t extends D {
    public static final Object b = new Object();
    public Object a;

    public C2955t(Object obj) {
        this.a = obj;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        return this.a != b;
    }

    @Override // java.util.Iterator
    public final Object next() {
        Object obj = this.a;
        Object obj2 = b;
        if (obj == obj2) {
            throw new NoSuchElementException();
        }
        this.a = obj2;
        return obj;
    }
}
