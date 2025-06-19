package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;

/* renamed from: com.google.android.gms.internal.ads.uw, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2718uw {
    public static final C2883yp a;

    static {
        try {
            Ps ps = new Ps();
            ps.r(C2933zw.b);
            ps.b(new C2163hy(Aw.class, InterfaceC2289kw.class, new Is(5)));
            ps.b(new C2163hy(Nw.class, InterfaceC2289kw.class, new Is(6)));
            ps.b(new C2163hy(Qw.class, InterfaceC2289kw.class, new Is(7)));
            ps.b(new C2163hy(Jw.class, InterfaceC2289kw.class, new Is(8)));
            ps.b(new C2163hy(Tw.class, InterfaceC2289kw.class, new Is(9)));
            ps.b(new C2163hy(C2162hx.class, InterfaceC2289kw.class, new Is(10)));
            ps.b(new C2163hy(C2074fx.class, InterfaceC2289kw.class, new Is(11)));
            a = new C2883yp(new C2291ky(ps), 5);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public static C2883yp a() throws GeneralSecurityException {
        if (Dx.a()) {
            throw new GeneralSecurityException("Cannot use non-FIPS-compliant AeadConfigurationV1 in FIPS mode");
        }
        return a;
    }
}
