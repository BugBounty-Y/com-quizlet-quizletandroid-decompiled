package com.google.android.gms.internal.ads;

import java.util.Arrays;

/* loaded from: classes2.dex */
public final class O implements InterfaceC2122h0 {
    public final int a;
    public final int[] b;
    public final long[] c;
    public final long[] d;
    public final long[] e;
    public final long f;

    public O(int[] iArr, long[] jArr, long[] jArr2, long[] jArr3) {
        this.b = iArr;
        this.c = jArr;
        this.d = jArr2;
        this.e = jArr3;
        int length = iArr.length;
        this.a = length;
        if (length <= 0) {
            this.f = 0L;
        } else {
            int i = length - 1;
            this.f = jArr2[i] + jArr3[i];
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public final C2078g0 b(long j) {
        long[] jArr = this.e;
        int iK = Yo.k(jArr, j, true);
        long j2 = jArr[iK];
        long[] jArr2 = this.c;
        C2166i0 c2166i0 = new C2166i0(j2, jArr2[iK]);
        if (j2 >= j || iK == this.a - 1) {
            return new C2078g0(c2166i0, c2166i0);
        }
        int i = iK + 1;
        return new C2078g0(c2166i0, new C2166i0(jArr[i], jArr2[i]));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public final boolean g() {
        return true;
    }

    public final String toString() {
        String string = Arrays.toString(this.b);
        String string2 = Arrays.toString(this.c);
        String string3 = Arrays.toString(this.e);
        String string4 = Arrays.toString(this.d);
        StringBuilder sb = new StringBuilder("ChunkIndex(length=");
        sb.append(this.a);
        sb.append(", sizes=");
        sb.append(string);
        sb.append(", offsets=");
        androidx.compose.ui.node.B.u(sb, string2, ", timeUs=", string3, ", durationsUs=");
        return android.support.v4.media.session.a.t(sb, string4, ")");
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public final long zza() {
        return this.f;
    }
}
