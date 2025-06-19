package com.google.common.collect;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3531s4;
import java.io.Serializable;

/* loaded from: classes2.dex */
public final class h implements Serializable {
    public final Object[] a;

    public h(Object[] objArr) {
        this.a = objArr;
    }

    public Object readResolve() {
        C3922e c3922e = j.b;
        Object[] objArr = this.a;
        if (objArr.length == 0) {
            return x.e;
        }
        Object[] objArr2 = (Object[]) objArr.clone();
        AbstractC3531s4.e(objArr2.length, objArr2);
        return j.k(objArr2.length, objArr2);
    }
}
