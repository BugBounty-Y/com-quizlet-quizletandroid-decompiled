package com.google.common.collect;

import androidx.appcompat.widget.C0122z;
import java.io.Serializable;
import java.util.Map;

/* loaded from: classes2.dex */
public final class l implements Serializable {
    public final Object[] a;
    public final Object[] b;

    public l(m mVar) {
        int i = ((C) mVar).f;
        Object[] objArr = new Object[i];
        Object[] objArr2 = new Object[i];
        com.google.android.gms.internal.common.g it2 = mVar.entrySet().iterator();
        int i2 = 0;
        while (it2.hasNext()) {
            Map.Entry entry = (Map.Entry) it2.next();
            objArr[i2] = entry.getKey();
            objArr2[i2] = entry.getValue();
            i2++;
        }
        this.a = objArr;
        this.b = objArr2;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public final Object readResolve() {
        Object[] objArr = this.a;
        boolean z = objArr instanceof o;
        Object[] objArr2 = this.b;
        if (!z) {
            C0122z c0122z = new C0122z(objArr.length);
            for (int i = 0; i < objArr.length; i++) {
                c0122z.u(objArr[i], objArr2[i]);
            }
            return c0122z.h();
        }
        o oVar = (o) objArr;
        C0122z c0122z2 = new C0122z(oVar.size());
        com.google.android.gms.internal.common.g it2 = oVar.iterator();
        com.google.android.gms.internal.common.g it3 = ((AbstractC3923f) objArr2).iterator();
        while (it2.hasNext()) {
            c0122z2.u(it2.next(), it3.next());
        }
        return c0122z2.h();
    }
}
