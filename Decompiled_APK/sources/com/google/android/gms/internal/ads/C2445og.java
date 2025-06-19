package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.og, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2445og extends AbstractC1754Pf {
    /* JADX WARN: Removed duplicated region for block: B:15:0x0032  */
    @Override // com.google.android.gms.internal.ads.InterfaceC1688Ef
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void c(java.nio.ByteBuffer r12) {
        /*
            Method dump skipped, instructions count: 259
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2445og.c(java.nio.ByteBuffer):void");
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1754Pf
    public final C2229jf d(C2229jf c2229jf) throws zzcm {
        int i = c2229jf.c;
        if (i != 3) {
            if (i == 2) {
                return C2229jf.e;
            }
            if (i != 268435456 && i != 21 && i != 1342177280 && i != 22 && i != 1610612736 && i != 4) {
                throw new zzcm("Unhandled input format:", c2229jf);
            }
        }
        return new C2229jf(c2229jf.a, c2229jf.b, 2);
    }
}
