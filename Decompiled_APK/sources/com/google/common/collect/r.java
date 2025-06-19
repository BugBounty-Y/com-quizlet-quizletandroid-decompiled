package com.google.common.collect;

/* loaded from: classes2.dex */
public final class r extends AbstractC3918a {
    public static final r e = new r(new Object[0]);
    public final Object[] d;

    public r(Object[] objArr) {
        super(objArr.length, 0);
        this.d = objArr;
    }

    @Override // com.google.common.collect.AbstractC3918a
    public final Object a(int i) {
        return this.d[i];
    }
}
