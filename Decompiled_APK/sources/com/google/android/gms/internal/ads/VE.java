package com.google.android.gms.internal.ads;

import java.util.Arrays;
import java.util.List;

/* loaded from: classes2.dex */
public final class VE implements BF {
    public final Bu a;
    public long b;

    public VE(List list, List list2) {
        C2244ju c2244ju = AbstractC2330lu.b;
        AbstractC2543qs.g(4, "initialCapacity");
        Object[] objArrCopyOf = new Object[4];
        int i = 0;
        AbstractC1795We.B(list.size() == list2.size());
        int i2 = 0;
        while (i < list.size()) {
            UE ue = new UE((BF) list.get(i), (List) list2.get(i));
            int length = objArrCopyOf.length;
            int i3 = i2 + 1;
            int iH = AbstractC2027eu.h(length, i3);
            if (iH > length) {
                objArrCopyOf = Arrays.copyOf(objArrCopyOf, iH);
            }
            objArrCopyOf[i2] = ue;
            i++;
            i2 = i3;
        }
        this.a = AbstractC2330lu.m(i2, objArrCopyOf);
        this.b = -9223372036854775807L;
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final long a() {
        int i = 0;
        long jMin = Long.MAX_VALUE;
        while (true) {
            Bu bu = this.a;
            if (i >= bu.d) {
                break;
            }
            long jA = ((UE) bu.get(i)).a.a();
            if (jA != Long.MIN_VALUE) {
                jMin = Math.min(jMin, jA);
            }
            i++;
        }
        if (jMin == Long.MAX_VALUE) {
            return Long.MIN_VALUE;
        }
        return jMin;
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final long b() {
        int i = 0;
        long jMin = Long.MAX_VALUE;
        long jMin2 = Long.MAX_VALUE;
        while (true) {
            Bu bu = this.a;
            if (i >= bu.d) {
                break;
            }
            UE ue = (UE) bu.get(i);
            long jB = ue.b();
            AbstractC2330lu abstractC2330lu = ue.b;
            if ((abstractC2330lu.contains(1) || abstractC2330lu.contains(2) || abstractC2330lu.contains(4)) && jB != Long.MIN_VALUE) {
                jMin = Math.min(jMin, jB);
            }
            if (jB != Long.MIN_VALUE) {
                jMin2 = Math.min(jMin2, jB);
            }
            i++;
        }
        if (jMin != Long.MAX_VALUE) {
            this.b = jMin;
            return jMin;
        }
        if (jMin2 == Long.MAX_VALUE) {
            return Long.MIN_VALUE;
        }
        long j = this.b;
        return j != -9223372036854775807L ? j : jMin2;
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final void d(long j) {
        int i = 0;
        while (true) {
            Bu bu = this.a;
            if (i >= bu.d) {
                return;
            }
            ((UE) bu.get(i)).d(j);
            i++;
        }
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final boolean k(C2607sD c2607sD) {
        boolean zK;
        boolean z = false;
        do {
            long jA = a();
            if (jA == Long.MIN_VALUE) {
                break;
            }
            int i = 0;
            zK = false;
            while (true) {
                Bu bu = this.a;
                if (i >= bu.d) {
                    break;
                }
                long jA2 = ((UE) bu.get(i)).a.a();
                boolean z2 = jA2 != Long.MIN_VALUE && jA2 <= c2607sD.a;
                if (jA2 == jA || z2) {
                    zK |= ((UE) bu.get(i)).a.k(c2607sD);
                }
                i++;
            }
            z |= zK;
        } while (zK);
        return z;
    }

    @Override // com.google.android.gms.internal.ads.BF
    public final boolean o() {
        int i = 0;
        while (true) {
            Bu bu = this.a;
            if (i >= bu.d) {
                return false;
            }
            if (((UE) bu.get(i)).a.o()) {
                return true;
            }
            i++;
        }
    }
}
