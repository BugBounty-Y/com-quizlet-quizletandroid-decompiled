package com.google.common.collect;

import java.io.Serializable;

/* renamed from: com.google.common.collect.e, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3922e extends AbstractC3918a {
    public final /* synthetic */ int d = 0;
    public final Serializable e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public C3922e(int i, Iterable[] iterableArr) {
        super(i, 0);
        this.e = iterableArr;
    }

    @Override // com.google.common.collect.AbstractC3918a
    public final Object a(int i) {
        switch (this.d) {
            case 0:
                return ((Iterable[]) this.e)[i].iterator();
            default:
                return ((j) this.e).get(i);
        }
    }

    public C3922e(j jVar, int i) {
        super(jVar.size(), i);
        this.e = jVar;
    }
}
