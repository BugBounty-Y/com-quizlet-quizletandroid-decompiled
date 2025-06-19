package com.google.android.gms.internal.ads;

import java.util.Arrays;
import java.util.Iterator;
import java.util.Objects;

/* renamed from: com.google.android.gms.internal.ads.nu, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2416nu extends AbstractC2027eu {
    public Object[] e;
    public int f;

    @Override // com.google.android.gms.internal.ads.AbstractC2027eu
    public final /* bridge */ /* synthetic */ AbstractC2027eu d(Object obj) {
        j(obj);
        return this;
    }

    public final void j(Object obj) {
        obj.getClass();
        if (this.e != null) {
            int iK = AbstractC2459ou.k(this.c);
            Object[] objArr = this.e;
            if (iK <= objArr.length) {
                int length = objArr.length - 1;
                int iHashCode = obj.hashCode();
                int iA = AbstractC2457os.a(iHashCode);
                while (true) {
                    int i = iA & length;
                    Object[] objArr2 = this.e;
                    Object obj2 = objArr2[i];
                    if (obj2 == null) {
                        objArr2[i] = obj;
                        this.f += iHashCode;
                        c(obj);
                        return;
                    } else if (obj2.equals(obj)) {
                        return;
                    } else {
                        iA = i + 1;
                    }
                }
            }
        }
        this.e = null;
        c(obj);
    }

    public final void k(Iterable iterable) {
        iterable.getClass();
        if (this.e == null) {
            f(iterable);
            return;
        }
        Iterator it2 = iterable.iterator();
        while (it2.hasNext()) {
            j(it2.next());
        }
    }

    public final AbstractC2459ou l() {
        AbstractC2459ou abstractC2459ouO;
        int i = this.c;
        if (i == 0) {
            return Hu.j;
        }
        if (i == 1) {
            Object obj = this.b[0];
            Objects.requireNonNull(obj);
            return new Nu(obj);
        }
        if (this.e == null || AbstractC2459ou.k(i) != this.e.length) {
            abstractC2459ouO = AbstractC2459ou.o(this.c, this.b);
            this.c = abstractC2459ouO.size();
        } else {
            int i2 = this.c;
            Object[] objArrCopyOf = this.b;
            int length = objArrCopyOf.length;
            if (i2 < (length >> 1) + (length >> 2)) {
                objArrCopyOf = Arrays.copyOf(objArrCopyOf, i2);
            }
            abstractC2459ouO = new Hu(objArrCopyOf, this.f, this.e, r6.length - 1, this.c);
        }
        this.d = true;
        this.e = null;
        return abstractC2459ouO;
    }
}
