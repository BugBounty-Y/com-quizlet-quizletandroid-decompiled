package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.security.GeneralSecurityException;

/* loaded from: classes2.dex */
public final class Nx extends AbstractC2025es {
    public final C2377my c;
    public final C2604sA d;

    public Nx(C2377my c2377my) throws GeneralSecurityException {
        C2604sA c2604sAA;
        super(9);
        int i = Lx.b[AbstractC0147y.k(c2377my.d)];
        this.c = c2377my;
        Yz yz = Yz.RAW;
        Yz yz2 = c2377my.e;
        if (yz2.equals(yz)) {
            c2604sAA = C2604sA.a(new byte[0]);
        } else {
            boolean zEquals = yz2.equals(Yz.TINK);
            Integer num = c2377my.f;
            if (zEquals) {
                c2604sAA = Yx.b(num.intValue());
            } else {
                if (!yz2.equals(Yz.LEGACY) && !yz2.equals(Yz.CRUNCHY)) {
                    throw new GeneralSecurityException("Unknown output prefix type");
                }
                c2604sAA = Yx.a(num.intValue());
            }
        }
        this.d = c2604sAA;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2025es
    public final AbstractC2547qw g() {
        C2377my c2377my = this.c;
        return new Mx(c2377my.a, c2377my.e);
    }
}
