package com.google.android.gms.internal.ads;

import android.util.Pair;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes2.dex */
public final class LD extends A9 {
    public static final /* synthetic */ int k = 0;
    public final int b;
    public final CF c;
    public final int d;
    public final int e;
    public final int[] f;
    public final int[] g;
    public final A9[] h;
    public final Object[] i;
    public final HashMap j;

    public LD(A9[] a9Arr, Object[] objArr, CF cf) {
        this.c = cf;
        this.b = cf.b.length;
        this.h = a9Arr;
        int length = a9Arr.length;
        this.f = new int[length];
        this.g = new int[length];
        this.i = objArr;
        this.j = new HashMap();
        int i = 0;
        int iC = 0;
        int iB = 0;
        int i2 = 0;
        while (i < a9Arr.length) {
            A9 a9 = a9Arr[i];
            this.h[i2] = a9;
            this.g[i2] = iC;
            this.f[i2] = iB;
            iC += a9.c();
            iB += this.h[i2].b();
            this.j.put(objArr[i2], Integer.valueOf(i2));
            i++;
            i2++;
        }
        this.d = iC;
        this.e = iB;
    }

    @Override // com.google.android.gms.internal.ads.A9
    public final int a(Object obj) {
        int iA;
        if (obj instanceof Pair) {
            Pair pair = (Pair) obj;
            Object obj2 = pair.first;
            Object obj3 = pair.second;
            Integer num = (Integer) this.j.get(obj2);
            int iIntValue = num == null ? -1 : num.intValue();
            if (iIntValue != -1 && (iA = this.h[iIntValue].a(obj3)) != -1) {
                return this.f[iIntValue] + iA;
            }
        }
        return -1;
    }

    @Override // com.google.android.gms.internal.ads.A9
    public final int b() {
        return this.e;
    }

    @Override // com.google.android.gms.internal.ads.A9
    public final int c() {
        return this.d;
    }

    @Override // com.google.android.gms.internal.ads.A9
    public final C2303l9 d(int i, C2303l9 c2303l9, boolean z) {
        int[] iArr = this.f;
        int iJ = Yo.j(iArr, i + 1, false, false);
        int i2 = this.g[iJ];
        this.h[iJ].d(i - iArr[iJ], c2303l9, z);
        c2303l9.c += i2;
        if (z) {
            Object obj = this.i[iJ];
            Object obj2 = c2303l9.b;
            obj2.getClass();
            c2303l9.b = Pair.create(obj, obj2);
        }
        return c2303l9;
    }

    @Override // com.google.android.gms.internal.ads.A9
    public final C2518q9 e(int i, C2518q9 c2518q9, long j) {
        int[] iArr = this.g;
        int iJ = Yo.j(iArr, i + 1, false, false);
        int i2 = iArr[iJ];
        int i3 = this.f[iJ];
        this.h[iJ].e(i - i2, c2518q9, j);
        Object objCreate = this.i[iJ];
        if (!C2518q9.m.equals(c2518q9.a)) {
            objCreate = Pair.create(objCreate, c2518q9.a);
        }
        c2518q9.a = objCreate;
        c2518q9.k += i3;
        c2518q9.l += i3;
        return c2518q9;
    }

    @Override // com.google.android.gms.internal.ads.A9
    public final Object f(int i) {
        int[] iArr = this.f;
        int iJ = Yo.j(iArr, i + 1, false, false);
        return Pair.create(this.i[iJ], this.h[iJ].f(i - iArr[iJ]));
    }

    @Override // com.google.android.gms.internal.ads.A9
    public final int g(boolean z) {
        if (this.b != 0) {
            int iP = 0;
            if (z) {
                int[] iArr = this.c.b;
                iP = iArr.length > 0 ? iArr[0] : -1;
            }
            do {
                A9[] a9Arr = this.h;
                if (!a9Arr[iP].o()) {
                    return a9Arr[iP].g(z) + this.g[iP];
                }
                iP = p(iP, z);
            } while (iP != -1);
        }
        return -1;
    }

    @Override // com.google.android.gms.internal.ads.A9
    public final int h(boolean z) {
        int iQ;
        int i = this.b;
        if (i != 0) {
            if (z) {
                int[] iArr = this.c.b;
                int length = iArr.length;
                iQ = length > 0 ? iArr[length - 1] : -1;
            } else {
                iQ = i - 1;
            }
            do {
                A9[] a9Arr = this.h;
                if (!a9Arr[iQ].o()) {
                    return a9Arr[iQ].h(z) + this.g[iQ];
                }
                iQ = q(iQ, z);
            } while (iQ != -1);
        }
        return -1;
    }

    @Override // com.google.android.gms.internal.ads.A9
    public final int j(int i, int i2, boolean z) {
        int[] iArr = this.g;
        int iJ = Yo.j(iArr, i + 1, false, false);
        int i3 = iArr[iJ];
        A9[] a9Arr = this.h;
        int iJ2 = a9Arr[iJ].j(i - i3, i2 != 2 ? i2 : 0, z);
        if (iJ2 != -1) {
            return i3 + iJ2;
        }
        int iP = p(iJ, z);
        while (iP != -1 && a9Arr[iP].o()) {
            iP = p(iP, z);
        }
        if (iP != -1) {
            return a9Arr[iP].g(z) + iArr[iP];
        }
        if (i2 == 2) {
            return g(z);
        }
        return -1;
    }

    @Override // com.google.android.gms.internal.ads.A9
    public final int k(int i) {
        int[] iArr = this.g;
        int iJ = Yo.j(iArr, i + 1, false, false);
        int i2 = iArr[iJ];
        A9[] a9Arr = this.h;
        int iK = a9Arr[iJ].k(i - i2);
        if (iK != -1) {
            return i2 + iK;
        }
        int iQ = q(iJ, false);
        while (iQ != -1 && a9Arr[iQ].o()) {
            iQ = q(iQ, false);
        }
        if (iQ == -1) {
            return -1;
        }
        return a9Arr[iQ].h(false) + iArr[iQ];
    }

    @Override // com.google.android.gms.internal.ads.A9
    public final C2303l9 n(Object obj, C2303l9 c2303l9) {
        Pair pair = (Pair) obj;
        Object obj2 = pair.first;
        Object obj3 = pair.second;
        Integer num = (Integer) this.j.get(obj2);
        int iIntValue = num == null ? -1 : num.intValue();
        int i = this.g[iIntValue];
        this.h[iIntValue].n(obj3, c2303l9);
        c2303l9.c += i;
        c2303l9.b = obj;
        return c2303l9;
    }

    public final int p(int i, boolean z) {
        if (!z) {
            if (i >= this.b - 1) {
                return -1;
            }
            return i + 1;
        }
        CF cf = this.c;
        int i2 = cf.c[i] + 1;
        int[] iArr = cf.b;
        if (i2 < iArr.length) {
            return iArr[i2];
        }
        return -1;
    }

    public final int q(int i, boolean z) {
        if (!z) {
            if (i <= 0) {
                return -1;
            }
            return i - 1;
        }
        CF cf = this.c;
        int i2 = cf.c[i] - 1;
        if (i2 >= 0) {
            return cf.b[i2];
        }
        return -1;
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public LD(List list, CF cf) {
        A9[] a9Arr = new A9[list.size()];
        Iterator it2 = list.iterator();
        int i = 0;
        int i2 = 0;
        while (it2.hasNext()) {
            a9Arr[i2] = ((InterfaceC2865yD) it2.next()).zza();
            i2++;
        }
        Object[] objArr = new Object[list.size()];
        Iterator it3 = list.iterator();
        while (it3.hasNext()) {
            objArr[i] = ((InterfaceC2865yD) it3.next()).zzb();
            i++;
        }
        this(a9Arr, objArr, cf);
    }
}
