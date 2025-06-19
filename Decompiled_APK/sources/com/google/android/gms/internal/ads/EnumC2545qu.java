package com.google.android.gms.internal.ads;

import java.util.Iterator;
import java.util.NoSuchElementException;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* renamed from: com.google.android.gms.internal.ads.qu, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class EnumC2545qu implements Iterator {
    public static final EnumC2545qu a;
    public static final /* synthetic */ EnumC2545qu[] b;

    static {
        EnumC2545qu enumC2545qu = new EnumC2545qu("INSTANCE", 0);
        a = enumC2545qu;
        b = new EnumC2545qu[]{enumC2545qu};
    }

    public static EnumC2545qu[] values() {
        return (EnumC2545qu[]) b.clone();
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        return false;
    }

    @Override // java.util.Iterator
    public final Object next() {
        throw new NoSuchElementException();
    }

    @Override // java.util.Iterator
    public final void remove() {
        AbstractC1981ds.L("no calls to next() since the last call to remove()", false);
    }
}
