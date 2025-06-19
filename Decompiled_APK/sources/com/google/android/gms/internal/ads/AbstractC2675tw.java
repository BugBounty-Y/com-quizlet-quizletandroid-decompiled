package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;

/* renamed from: com.google.android.gms.internal.ads.tw, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2675tw {
    static {
        int i = Zz.zza;
        try {
            a();
        } catch (GeneralSecurityException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    public static void a() {
        Wx wx = Wx.b;
        wx.b(C2933zw.b);
        wx.a(C2933zw.c);
        Fy.a();
        int i = Dw.e;
        if (!AbstractC1981ds.j(i)) {
            throw new GeneralSecurityException("Can not use AES-CTR-HMAC in FIPS-mode, as BoringCrypto module is not available.");
        }
        C1944cy c1944cy = AbstractC2333lx.a;
        Xx xx = Xx.b;
        xx.h(AbstractC2333lx.a);
        xx.g(AbstractC2333lx.b);
        xx.f(AbstractC2333lx.c);
        xx.e(AbstractC2333lx.d);
        wx.a(Dw.a);
        Vx vx = Vx.b;
        HashMap map = new HashMap();
        map.put("AES128_CTR_HMAC_SHA256", AbstractC2030ex.e);
        C2084g6 c2084g6 = new C2084g6(6);
        c2084g6.d(16);
        c2084g6.h(32);
        c2084g6.l(16);
        c2084g6.i(16);
        Ew ew = Ew.e;
        c2084g6.e = ew;
        Gw gw = Gw.e;
        c2084g6.f = gw;
        map.put("AES128_CTR_HMAC_SHA256_RAW", c2084g6.n());
        map.put("AES256_CTR_HMAC_SHA256", AbstractC2030ex.f);
        C2084g6 c2084g62 = new C2084g6(6);
        c2084g62.d(32);
        c2084g62.h(32);
        c2084g62.l(32);
        c2084g62.i(16);
        c2084g62.e = ew;
        c2084g62.f = gw;
        map.put("AES256_CTR_HMAC_SHA256_RAW", c2084g62.n());
        vx.b(Collections.unmodifiableMap(map));
        Sx sx = Sx.b;
        sx.a(Dw.c, Hw.class);
        Qx qx = Qx.b;
        qx.b(Dw.d, Hw.class);
        Fx fx = Fx.d;
        fx.c(Dw.b, i);
        int i2 = Ow.e;
        if (!AbstractC1981ds.j(i2)) {
            throw new GeneralSecurityException("Can not use AES-GCM in FIPS-mode, as BoringCrypto module is not available.");
        }
        xx.h(AbstractC2462ox.a);
        xx.g(AbstractC2462ox.b);
        xx.f(AbstractC2462ox.c);
        xx.e(AbstractC2462ox.d);
        wx.a(Ow.a);
        HashMap map2 = new HashMap();
        map2.put("AES128_GCM", AbstractC2030ex.a);
        com.quizlet.data.repository.metering.j jVar = new com.quizlet.data.repository.metering.j();
        jVar.f();
        jVar.g(16);
        jVar.h();
        C2332lw c2332lw = C2332lw.h;
        jVar.d = c2332lw;
        map2.put("AES128_GCM_RAW", jVar.i());
        map2.put("AES256_GCM", AbstractC2030ex.b);
        com.quizlet.data.repository.metering.j jVar2 = new com.quizlet.data.repository.metering.j();
        jVar2.f();
        jVar2.g(32);
        jVar2.h();
        jVar2.d = c2332lw;
        map2.put("AES256_GCM_RAW", jVar2.i());
        vx.b(Collections.unmodifiableMap(map2));
        sx.a(Ow.c, Pw.class);
        qx.b(Ow.d, Pw.class);
        fx.c(Ow.b, i2);
        if (Dx.a()) {
            return;
        }
        C2163hy c2163hy = Kw.a;
        if (!AbstractC1981ds.j(1)) {
            throw new GeneralSecurityException("Registering AES EAX is not supported in FIPS mode");
        }
        xx.h(AbstractC2376mx.a);
        xx.g(AbstractC2376mx.b);
        xx.f(AbstractC2376mx.c);
        xx.e(AbstractC2376mx.d);
        wx.a(Kw.a);
        HashMap map3 = new HashMap();
        map3.put("AES128_EAX", AbstractC2030ex.c);
        com.quizlet.data.repository.explanations.textbook.a aVar = new com.quizlet.data.repository.explanations.textbook.a(4);
        aVar.g(16);
        aVar.i(16);
        aVar.j();
        Lw lw = Lw.e;
        aVar.d = lw;
        map3.put("AES128_EAX_RAW", aVar.l());
        map3.put("AES256_EAX", AbstractC2030ex.d);
        com.quizlet.data.repository.explanations.textbook.a aVar2 = new com.quizlet.data.repository.explanations.textbook.a(4);
        aVar2.g(16);
        aVar2.i(32);
        aVar2.j();
        aVar2.d = lw;
        map3.put("AES256_EAX_RAW", aVar2.l());
        vx.b(Collections.unmodifiableMap(map3));
        qx.b(Kw.c, Mw.class);
        fx.b(Kw.b);
        C2163hy c2163hy2 = Rw.a;
        if (!AbstractC1981ds.j(1)) {
            throw new GeneralSecurityException("Registering AES GCM SIV is not supported in FIPS mode");
        }
        xx.h(AbstractC2548qx.a);
        xx.g(AbstractC2548qx.b);
        xx.f(AbstractC2548qx.c);
        xx.e(AbstractC2548qx.d);
        HashMap map4 = new HashMap();
        Ew ew2 = Ew.j;
        Ew ew3 = Ew.h;
        map4.put("AES128_GCM_SIV", new Sw(16, ew3));
        map4.put("AES128_GCM_SIV_RAW", new Sw(16, ew2));
        map4.put("AES256_GCM_SIV", new Sw(32, ew3));
        map4.put("AES256_GCM_SIV_RAW", new Sw(32, ew2));
        vx.b(Collections.unmodifiableMap(map4));
        sx.a(Rw.c, Sw.class);
        qx.b(Rw.b, Sw.class);
        wx.a(Rw.a);
        fx.b(Rw.d);
        C2163hy c2163hy3 = Uw.a;
        if (!AbstractC1981ds.j(1)) {
            throw new GeneralSecurityException("Registering ChaCha20Poly1305 is not supported in FIPS mode");
        }
        xx.h(AbstractC2633sx.a);
        xx.g(AbstractC2633sx.b);
        xx.f(AbstractC2633sx.c);
        xx.e(AbstractC2633sx.d);
        wx.a(Uw.a);
        qx.b(Uw.b, Vw.class);
        HashMap map5 = new HashMap();
        map5.put("CHACHA20_POLY1305", new Vw(Gw.f));
        map5.put("CHACHA20_POLY1305_RAW", new Vw(Gw.h));
        vx.b(Collections.unmodifiableMap(map5));
        fx.b(Uw.c);
        C2163hy c2163hy4 = Ww.a;
        if (!AbstractC1981ds.j(1)) {
            throw new GeneralSecurityException("Registering KMS AEAD is not supported in FIPS mode");
        }
        xx.h(AbstractC1856ax.a);
        xx.g(AbstractC1856ax.b);
        xx.f(AbstractC1856ax.c);
        xx.e(AbstractC1856ax.d);
        wx.a(Ww.a);
        qx.b(Ww.c, Zw.class);
        fx.b(Ww.b);
        Kx kx = Xw.a;
        if (!AbstractC1981ds.j(1)) {
            throw new GeneralSecurityException("Registering KMS Envelope AEAD is not supported in FIPS mode");
        }
        xx.h(AbstractC1986dx.a);
        xx.g(AbstractC1986dx.b);
        xx.f(AbstractC1986dx.c);
        xx.e(AbstractC1986dx.d);
        qx.b(Xw.b, C1943cx.class);
        wx.a(Xw.c);
        fx.b(Xw.a);
        C2163hy c2163hy5 = AbstractC2204ix.a;
        if (!AbstractC1981ds.j(1)) {
            throw new GeneralSecurityException("Registering XChaCha20Poly1305 is not supported in FIPS mode");
        }
        xx.h(Ax.a);
        xx.g(Ax.b);
        xx.f(Ax.c);
        xx.e(Ax.d);
        wx.a(AbstractC2204ix.a);
        HashMap map6 = new HashMap();
        map6.put("XCHACHA20_POLY1305", new C2247jx(Lw.h));
        map6.put("XCHACHA20_POLY1305_RAW", new C2247jx(Lw.j));
        vx.b(Collections.unmodifiableMap(map6));
        qx.b(AbstractC2204ix.d, C2247jx.class);
        sx.a(AbstractC2204ix.c, C2247jx.class);
        fx.b(AbstractC2204ix.b);
        xx.h(AbstractC2934zx.a);
        xx.g(AbstractC2934zx.b);
        xx.f(AbstractC2934zx.c);
        xx.e(AbstractC2934zx.d);
        HashMap map7 = new HashMap();
        map7.put("XAES_256_GCM_192_BIT_NONCE", AbstractC2030ex.g);
        map7.put("XAES_256_GCM_192_BIT_NONCE_NO_PREFIX", AbstractC2030ex.h);
        map7.put("XAES_256_GCM_160_BIT_NONCE_NO_PREFIX", AbstractC2030ex.i);
        map7.put("X_AES_GCM_8_BYTE_SALT_NO_PREFIX", AbstractC2030ex.j);
        vx.b(Collections.unmodifiableMap(map7));
        wx.a(AbstractC2096gb.x);
        qx.b(AbstractC2096gb.w, C2118gx.class);
    }
}
