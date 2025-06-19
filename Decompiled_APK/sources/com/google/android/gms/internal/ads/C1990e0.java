package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.e0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1990e0 implements InterfaceC2122h0 {
    public final androidx.compose.ui.input.pointer.util.b a;
    public final androidx.compose.ui.input.pointer.util.b b;
    public final long c;

    public C1990e0(long j, long[] jArr, long[] jArr2) {
        int length = jArr.length;
        int length2 = jArr2.length;
        AbstractC1795We.B(length == length2);
        if (length2 <= 0 || jArr2[0] <= 0) {
            this.a = new androidx.compose.ui.input.pointer.util.b(length2);
            this.b = new androidx.compose.ui.input.pointer.util.b(length2);
        } else {
            int i = length2 + 1;
            androidx.compose.ui.input.pointer.util.b bVar = new androidx.compose.ui.input.pointer.util.b(i);
            this.a = bVar;
            androidx.compose.ui.input.pointer.util.b bVar2 = new androidx.compose.ui.input.pointer.util.b(i);
            this.b = bVar2;
            bVar.e(0L);
            bVar2.e(0L);
        }
        this.a.f(jArr);
        this.b.f(jArr2);
        this.c = j;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public final C2078g0 b(long j) {
        androidx.compose.ui.input.pointer.util.b bVar = this.b;
        int i = bVar.a;
        if (i == 0) {
            C2166i0 c2166i0 = C2166i0.c;
            return new C2078g0(c2166i0, c2166i0);
        }
        String str = Yo.a;
        int i2 = i - 1;
        int i3 = 0;
        int i4 = 0;
        while (i4 <= i2) {
            int i5 = (i4 + i2) >>> 1;
            if (bVar.d(i5) < j) {
                i4 = i5 + 1;
            } else {
                i2 = i5 - 1;
            }
        }
        int i6 = i2 + 1;
        if (i6 < bVar.a && bVar.d(i6) == j) {
            i3 = i6;
        } else if (i2 != -1) {
            i3 = i2;
        }
        long jD = bVar.d(i3);
        androidx.compose.ui.input.pointer.util.b bVar2 = this.a;
        C2166i0 c2166i02 = new C2166i0(jD, bVar2.d(i3));
        if (jD == j || i3 == bVar.a - 1) {
            return new C2078g0(c2166i02, c2166i02);
        }
        int i7 = i3 + 1;
        return new C2078g0(c2166i02, new C2166i0(bVar.d(i7), bVar2.d(i7)));
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public final boolean g() {
        return this.b.a > 0;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2122h0
    public final long zza() {
        return this.c;
    }
}
