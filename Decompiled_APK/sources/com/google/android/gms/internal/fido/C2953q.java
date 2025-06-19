package com.google.android.gms.internal.fido;

import java.util.Iterator;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.fido.q, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2953q extends AbstractC2951o {
    public final /* synthetic */ r d;

    public C2953q(r rVar) {
        this.d = rVar;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final boolean contains(Object obj) {
        if (obj instanceof Map.Entry) {
            Map.Entry entry = (Map.Entry) obj;
            Object obj2 = this.d.get(entry.getKey());
            if (obj2 != null && obj2.equals(entry.getValue())) {
                return true;
            }
        }
        return false;
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2944h
    public final D e() {
        return k().listIterator(0);
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2951o, java.util.Collection, java.util.Set
    public final int hashCode() {
        return AbstractC2937a.b(this.d.entrySet());
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.lang.Iterable, java.util.Set
    public final /* synthetic */ Iterator iterator() {
        return k().listIterator(0);
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2951o
    public final AbstractC2949m m() {
        return new C2952p(this);
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.Set
    public final int size() {
        return this.d.d.size();
    }
}
