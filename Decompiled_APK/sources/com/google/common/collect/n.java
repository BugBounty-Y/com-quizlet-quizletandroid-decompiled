package com.google.common.collect;

import java.io.Serializable;

/* loaded from: classes2.dex */
public final class n implements Serializable {
    public final Object[] a;

    public n(Object[] objArr) {
        this.a = objArr;
    }

    public Object readResolve() {
        Object[] objArr = this.a;
        int length = objArr.length;
        return length != 0 ? length != 1 ? o.m(objArr.length, (Object[]) objArr.clone()) : new E(objArr[0]) : D.j;
    }
}
