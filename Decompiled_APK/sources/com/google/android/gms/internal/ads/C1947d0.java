package com.google.android.gms.internal.ads;

import androidx.camera.core.impl.C0186z;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.regex.Pattern;

/* renamed from: com.google.android.gms.internal.ads.d0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1947d0 implements InterfaceC1818a2 {
    public final Kn a;

    public C1947d0(int i) {
        switch (i) {
            case 1:
                this.a = new Kn();
                break;
            default:
                this.a = new Kn(10);
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1818a2
    public void a(byte[] bArr, int i, int i2, C0186z c0186z) {
        Gg ggA;
        Kn kn = this.a;
        kn.h(i + i2, bArr);
        kn.j(i);
        ArrayList arrayList = new ArrayList();
        while (kn.s() > 0) {
            AbstractC1795We.G(kn.s() >= 8, "Incomplete Mp4Webvtt Top Level box header found.");
            int iU = kn.u() - 8;
            if (kn.u() == 1987343459) {
                CharSequence charSequenceA = null;
                C2788wg c2788wgA = null;
                while (iU > 0) {
                    AbstractC1795We.G(iU >= 8, "Incomplete vtt cue box header found.");
                    int iU2 = kn.u();
                    int iU3 = kn.u();
                    int i3 = iU - 8;
                    int i4 = iU2 - 8;
                    byte[] bArr2 = kn.a;
                    int i5 = kn.b;
                    String str = Yo.a;
                    String str2 = new String(bArr2, i5, i4, StandardCharsets.UTF_8);
                    kn.k(i4);
                    if (iU3 == 1937011815) {
                        G2 g2 = new G2();
                        H2.f(str2, g2);
                        c2788wgA = g2.a();
                    } else if (iU3 == 1885436268) {
                        charSequenceA = H2.a(null, str2.trim(), Collections.EMPTY_LIST);
                    }
                    iU = i3 - i4;
                }
                if (charSequenceA == null) {
                    charSequenceA = "";
                }
                if (c2788wgA != null) {
                    c2788wgA.a = charSequenceA;
                    ggA = c2788wgA.a();
                } else {
                    Pattern pattern = H2.a;
                    G2 g22 = new G2();
                    g22.c = charSequenceA;
                    ggA = g22.a().a();
                }
                arrayList.add(ggA);
            } else {
                kn.k(iU);
            }
        }
        c0186z.mo10b(new X1(arrayList, -9223372036854775807L, -9223372036854775807L));
    }

    /* JADX WARN: Removed duplicated region for block: B:37:0x00bd  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x00cc  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x00d0  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.google.android.gms.internal.ads.K4 b(com.google.android.gms.internal.ads.P r18, com.google.android.gms.internal.ads.C1 r19) {
        /*
            Method dump skipped, instructions count: 291
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C1947d0.b(com.google.android.gms.internal.ads.P, com.google.android.gms.internal.ads.C1):com.google.android.gms.internal.ads.K4");
    }
}
