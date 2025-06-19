package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.x0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2809x0 implements InterfaceC2594s0 {
    public final Bu a;
    public final int b;

    public C2809x0(int i, Bu bu) {
        this.b = i;
        this.a = bu;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:75:0x01a1  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x01c2 A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.google.android.gms.internal.ads.C2809x0 b(int r19, com.google.android.gms.internal.ads.Kn r20) {
        /*
            Method dump skipped, instructions count: 568
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2809x0.b(int, com.google.android.gms.internal.ads.Kn):com.google.android.gms.internal.ads.x0");
    }

    public final InterfaceC2594s0 a(Class cls) {
        Bu bu = this.a;
        int i = bu.d;
        int i2 = 0;
        while (i2 < i) {
            InterfaceC2594s0 interfaceC2594s0 = (InterfaceC2594s0) bu.get(i2);
            i2++;
            if (interfaceC2594s0.getClass() == cls) {
                return interfaceC2594s0;
            }
        }
        return null;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2594s0
    public final int zza() {
        return this.b;
    }
}
