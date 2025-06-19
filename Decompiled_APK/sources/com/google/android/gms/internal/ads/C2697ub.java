package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.ub, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2697ub {
    public static final C2697ub b;
    public final AbstractC2330lu a;

    static {
        C2244ju c2244ju = AbstractC2330lu.b;
        b = new C2697ub(Bu.e);
        String str = Yo.a;
        Integer.toString(0, 36);
    }

    public C2697ub(AbstractC2330lu abstractC2330lu) {
        this.a = AbstractC2330lu.n(abstractC2330lu);
    }

    public final boolean a(int i) {
        int i2 = 0;
        while (true) {
            AbstractC2330lu abstractC2330lu = this.a;
            if (i2 >= abstractC2330lu.size()) {
                return false;
            }
            C2184ib c2184ib = (C2184ib) abstractC2330lu.get(i2);
            boolean[] zArr = c2184ib.e;
            int length = zArr.length;
            int i3 = 0;
            while (true) {
                if (i3 >= length) {
                    break;
                }
                if (!zArr[i3]) {
                    i3++;
                } else if (c2184ib.b.c == i) {
                    return true;
                }
            }
            i2++;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || C2697ub.class != obj.getClass()) {
            return false;
        }
        return this.a.equals(((C2697ub) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }
}
