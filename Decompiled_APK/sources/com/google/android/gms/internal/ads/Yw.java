package com.google.android.gms.internal.ads;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;

/* loaded from: classes2.dex */
public final class Yw extends AbstractC2761vw {
    public final Zw c;
    public final C2604sA d;
    public final Integer e;

    public Yw(Zw zw, C2604sA c2604sA, Integer num) {
        super(9);
        this.c = zw;
        this.d = c2604sA;
        this.e = num;
    }

    public static Yw S(Zw zw, Integer num) throws GeneralSecurityException {
        C2604sA c2604sAA;
        Lw lw = zw.b;
        if (lw == Lw.f) {
            if (num == null) {
                throw new GeneralSecurityException("For given Variant TINK the value of idRequirement must be non-null");
            }
            c2604sAA = C2604sA.a(ByteBuffer.allocate(5).put((byte) 1).putInt(num.intValue()).array());
        } else {
            if (lw != Lw.g) {
                throw new GeneralSecurityException("Unknown Variant: ".concat(lw.b));
            }
            if (num != null) {
                throw new GeneralSecurityException("For given Variant NO_PREFIX the value of idRequirement must be null");
            }
            c2604sAA = C2604sA.a(new byte[0]);
        }
        return new Yw(zw, c2604sAA, num);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2761vw
    public final C2604sA R() {
        return this.d;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2025es
    public final /* synthetic */ AbstractC2547qw g() {
        return this.c;
    }
}
