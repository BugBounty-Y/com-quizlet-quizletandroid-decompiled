package com.google.android.gms.internal.ads;

import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.HashMap;

/* loaded from: classes2.dex */
public abstract class Fy {
    static {
        int i = Zz.zza;
        try {
            a();
        } catch (GeneralSecurityException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    public static void a() throws GeneralSecurityException {
        Wx wx = Wx.b;
        wx.b(C2933zw.e);
        wx.a(C2933zw.f);
        wx.b(C2933zw.d);
        int i = By.f;
        if (!AbstractC1981ds.j(i)) {
            throw new GeneralSecurityException("Can not use HMAC in FIPS-mode, as BoringCrypto module is not available.");
        }
        C2272kf c2272kf = Ly.a;
        Xx xx = Xx.b;
        xx.h(Ly.c);
        xx.g(Ly.d);
        xx.f(Ly.e);
        xx.e(Ly.f);
        wx.a(By.a);
        wx.a(By.b);
        Vx vx = Vx.b;
        HashMap map = new HashMap();
        map.put("HMAC_SHA256_128BITTAG", Jy.a);
        com.quizlet.data.repository.studysetwithcreator.d dVar = new com.quizlet.data.repository.studysetwithcreator.d(4);
        dVar.f(32);
        dVar.g(16);
        Dy dy = Dy.e;
        dVar.d = dy;
        Cy cy = Cy.d;
        dVar.c = cy;
        map.put("HMAC_SHA256_128BITTAG_RAW", dVar.h());
        com.quizlet.data.repository.studysetwithcreator.d dVar2 = new com.quizlet.data.repository.studysetwithcreator.d(4);
        dVar2.f(32);
        dVar2.g(32);
        Dy dy2 = Dy.b;
        dVar2.d = dy2;
        dVar2.c = cy;
        map.put("HMAC_SHA256_256BITTAG", dVar2.h());
        com.quizlet.data.repository.studysetwithcreator.d dVar3 = new com.quizlet.data.repository.studysetwithcreator.d(4);
        dVar3.f(32);
        dVar3.g(32);
        dVar3.d = dy;
        dVar3.c = cy;
        map.put("HMAC_SHA256_256BITTAG_RAW", dVar3.h());
        com.quizlet.data.repository.studysetwithcreator.d dVar4 = new com.quizlet.data.repository.studysetwithcreator.d(4);
        dVar4.f(64);
        dVar4.g(16);
        dVar4.d = dy2;
        Cy cy2 = Cy.f;
        dVar4.c = cy2;
        map.put("HMAC_SHA512_128BITTAG", dVar4.h());
        com.quizlet.data.repository.studysetwithcreator.d dVar5 = new com.quizlet.data.repository.studysetwithcreator.d(4);
        dVar5.f(64);
        dVar5.g(16);
        dVar5.d = dy;
        dVar5.c = cy2;
        map.put("HMAC_SHA512_128BITTAG_RAW", dVar5.h());
        com.quizlet.data.repository.studysetwithcreator.d dVar6 = new com.quizlet.data.repository.studysetwithcreator.d(4);
        dVar6.f(64);
        dVar6.g(32);
        dVar6.d = dy2;
        dVar6.c = cy2;
        map.put("HMAC_SHA512_256BITTAG", dVar6.h());
        com.quizlet.data.repository.studysetwithcreator.d dVar7 = new com.quizlet.data.repository.studysetwithcreator.d(4);
        dVar7.f(64);
        dVar7.g(32);
        dVar7.d = dy;
        dVar7.c = cy2;
        map.put("HMAC_SHA512_256BITTAG_RAW", dVar7.h());
        map.put("HMAC_SHA512_512BITTAG", Jy.b);
        com.quizlet.data.repository.studysetwithcreator.d dVar8 = new com.quizlet.data.repository.studysetwithcreator.d(4);
        dVar8.f(64);
        dVar8.g(64);
        dVar8.d = dy;
        dVar8.c = cy2;
        map.put("HMAC_SHA512_512BITTAG_RAW", dVar8.h());
        vx.b(Collections.unmodifiableMap(map));
        Qx qx = Qx.b;
        qx.b(By.e, Ey.class);
        Sx.b.a(By.d, Ey.class);
        Fx fx = Fx.d;
        fx.c(By.c, i);
        if (Dx.a()) {
            return;
        }
        Cw cw = AbstractC2849xy.a;
        if (!AbstractC1981ds.j(1)) {
            throw new GeneralSecurityException("Registering AES CMAC is not supported in FIPS mode");
        }
        xx.h(Ky.a);
        xx.g(Ky.b);
        xx.f(Ky.c);
        xx.e(Ky.d);
        qx.b(AbstractC2849xy.a, C2892yy.class);
        wx.a(AbstractC2849xy.b);
        wx.a(AbstractC2849xy.c);
        HashMap map2 = new HashMap();
        C2892yy c2892yy = Jy.c;
        map2.put("AES_CMAC", c2892yy);
        map2.put("AES256_CMAC", c2892yy);
        Iw iw = new Iw();
        iw.b(32);
        iw.d(16);
        iw.a = C2332lw.r;
        map2.put("AES256_CMAC_RAW", iw.i());
        vx.b(Collections.unmodifiableMap(map2));
        fx.b(AbstractC2849xy.d);
    }
}
