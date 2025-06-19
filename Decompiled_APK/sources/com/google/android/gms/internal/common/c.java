package com.google.android.gms.internal.common;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3524r3;

/* loaded from: classes2.dex */
public final class c extends e {
    public final transient e c;

    public c(e eVar) {
        this.c = eVar;
    }

    @Override // com.google.android.gms.internal.common.e, java.util.AbstractCollection, java.util.Collection, java.util.List
    public final boolean contains(Object obj) {
        return this.c.contains(obj);
    }

    @Override // com.google.android.gms.internal.common.e
    public final e g() {
        return this.c;
    }

    @Override // java.util.List
    public final Object get(int i) {
        e eVar = this.c;
        AbstractC3524r3.b(i, eVar.size());
        return eVar.get((eVar.size() - 1) - i);
    }

    @Override // com.google.android.gms.internal.common.e, java.util.List
    /* renamed from: h, reason: merged with bridge method [inline-methods] */
    public final e subList(int i, int i2) {
        e eVar = this.c;
        AbstractC3524r3.d(i, i2, eVar.size());
        return eVar.subList(eVar.size() - i2, eVar.size() - i).g();
    }

    @Override // com.google.android.gms.internal.common.e, java.util.List
    public final int indexOf(Object obj) {
        int iLastIndexOf = this.c.lastIndexOf(obj);
        if (iLastIndexOf >= 0) {
            return (r0.size() - 1) - iLastIndexOf;
        }
        return -1;
    }

    @Override // com.google.android.gms.internal.common.e, java.util.List
    public final int lastIndexOf(Object obj) {
        int iIndexOf = this.c.indexOf(obj);
        if (iIndexOf >= 0) {
            return (r0.size() - 1) - iIndexOf;
        }
        return -1;
    }

    @Override // java.util.AbstractCollection, java.util.Collection, java.util.List
    public final int size() {
        return this.c.size();
    }
}
