package com.google.android.gms.internal.ads;

import java.security.InvalidAlgorithmParameterException;
import java.util.Arrays;
import javax.crypto.spec.SecretKeySpec;

/* renamed from: com.google.android.gms.internal.ads.rA, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2561rA implements InterfaceC2504pw {
    public static final byte[] e = {0};
    public final My a;
    public final int b;
    public final byte[] c;
    public final byte[] d;

    public C2561rA(C2720uy c2720uy) {
        this.a = new C2476pA(((C2604sA) c2720uy.d.b).b());
        C2892yy c2892yy = c2720uy.c;
        this.b = c2892yy.b;
        this.c = c2720uy.e.b();
        if (c2892yy.c.equals(C2332lw.q)) {
            this.d = Arrays.copyOf(e, 1);
        } else {
            this.d = new byte[0];
        }
    }

    public C2561rA(Ay ay) {
        String strValueOf = String.valueOf(ay.c.d);
        this.a = new As("HMAC".concat(strValueOf), new SecretKeySpec(((C2604sA) ay.d.b).b(), "HMAC"));
        Ey ey = ay.c;
        this.b = ey.b;
        this.c = ay.e.b();
        if (ey.c.equals(Dy.d)) {
            this.d = Arrays.copyOf(e, 1);
        } else {
            this.d = new byte[0];
        }
    }

    public C2561rA(As as, int i) throws IllegalStateException, InvalidAlgorithmParameterException {
        this.a = as;
        this.b = i;
        this.c = new byte[0];
        this.d = new byte[0];
        as.a(i, new byte[0]);
    }
}
