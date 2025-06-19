package com.google.android.gms.internal.fido;

import java.util.AbstractMap;

/* renamed from: com.google.android.gms.internal.fido.p, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2952p extends AbstractC2949m {
    public final /* synthetic */ C2953q c;

    public C2952p(C2953q c2953q) {
        this.c = c2953q;
    }

    @Override // java.util.List
    public final /* bridge */ /* synthetic */ Object get(int i) {
        C2953q c2953q = this.c;
        return new AbstractMap.SimpleImmutableEntry(c2953q.d.c.f.get(i), c2953q.d.d.get(i));
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.c.d.d.size();
    }
}
