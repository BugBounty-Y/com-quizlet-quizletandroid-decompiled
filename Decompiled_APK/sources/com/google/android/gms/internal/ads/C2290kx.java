package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.comscore.streaming.EventType;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;

/* renamed from: com.google.android.gms.internal.ads.kx, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C2290kx implements InterfaceC1987dy, InterfaceC1857ay, Jx, Hx, InterfaceC2205iy {
    public final /* synthetic */ int a;

    public /* synthetic */ C2290kx(int i) {
        this.a = i;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2205iy, com.google.android.gms.internal.ads.Jx
    public Object a(AbstractC2025es abstractC2025es) throws GeneralSecurityException {
        if (((C2720uy) abstractC2025es).c.a != 32) {
            throw new GeneralSecurityException("AesCmacKey size wrong, must be 32 bytes");
        }
        C2935zy c2935zy = new C2935zy();
        if (AbstractC1981ds.j(1)) {
            return c2935zy;
        }
        throw new GeneralSecurityException("Can not use AES-CMAC in FIPS-mode.");
    }

    @Override // com.google.android.gms.internal.ads.Hx
    public AbstractC2025es f(C2377my c2377my) throws GeneralSecurityException {
        switch (this.a) {
            case 3:
                if (!c2377my.a.equals("type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey")) {
                    throw new IllegalArgumentException("Wrong type URL in call to AesCtrHmacAeadProtoSerialization.parseKey");
                }
                try {
                    BA ba = c2377my.c;
                    IA ia = IA.a;
                    C2305lB c2305lB = C2305lB.c;
                    Vy vyY = Vy.y(ba, IA.b);
                    if (vyY.w() != 0) {
                        throw new GeneralSecurityException("Only version 0 keys are accepted");
                    }
                    if (vyY.z().w() != 0) {
                        throw new GeneralSecurityException("Only version 0 keys inner AES CTR keys are accepted");
                    }
                    if (vyY.A().w() != 0) {
                        throw new GeneralSecurityException("Only version 0 keys inner HMAC keys are accepted");
                    }
                    C2084g6 c2084g6 = new C2084g6(6);
                    c2084g6.d(vyY.z().A().g());
                    c2084g6.h(vyY.A().B().g());
                    c2084g6.i(vyY.z().z().w());
                    c2084g6.l(vyY.A().A().w());
                    c2084g6.e = AbstractC2333lx.a(vyY.A().A().x());
                    c2084g6.f = AbstractC2333lx.b(c2377my.e);
                    Hw hwN = c2084g6.n();
                    com.quizlet.data.repository.explanations.question.a aVar = new com.quizlet.data.repository.explanations.question.a();
                    aVar.a = hwN;
                    aVar.b = C2883yp.f(vyY.z().A().a());
                    aVar.c = C2883yp.f(vyY.A().B().a());
                    aVar.d = c2377my.f;
                    return aVar.i();
                } catch (zzgzh unused) {
                    throw new GeneralSecurityException("Parsing AesCtrHmacAeadKey failed");
                }
            case 7:
                if (!c2377my.a.equals("type.googleapis.com/google.crypto.tink.AesEaxKey")) {
                    throw new IllegalArgumentException("Wrong type URL in call to AesEaxProtoSerialization.parseKey");
                }
                try {
                    BA ba2 = c2377my.c;
                    IA ia2 = IA.a;
                    C2305lB c2305lB2 = C2305lB.c;
                    C2076fz c2076fzY = C2076fz.y(ba2, IA.b);
                    if (c2076fzY.w() != 0) {
                        throw new GeneralSecurityException("Only version 0 keys are accepted");
                    }
                    com.quizlet.data.repository.explanations.textbook.a aVar2 = new com.quizlet.data.repository.explanations.textbook.a(4);
                    aVar2.i(c2076fzY.A().g());
                    aVar2.g(c2076fzY.z().w());
                    aVar2.j();
                    aVar2.d = AbstractC2376mx.a(c2377my.e);
                    Mw mwL = aVar2.l();
                    Iw iw = new Iw(false);
                    iw.c = mwL;
                    iw.a = C2883yp.f(c2076fzY.A().a());
                    iw.b = c2377my.f;
                    return iw.e();
                } catch (zzgzh unused2) {
                    throw new GeneralSecurityException("Parsing AesEaxcKey failed");
                }
            case 11:
                if (!c2377my.a.equals("type.googleapis.com/google.crypto.tink.AesGcmKey")) {
                    throw new IllegalArgumentException("Wrong type URL in call to AesGcmProtoSerialization.parseKey");
                }
                try {
                    BA ba3 = c2377my.c;
                    IA ia3 = IA.a;
                    C2305lB c2305lB3 = C2305lB.c;
                    C2335lz c2335lzY = C2335lz.y(ba3, IA.b);
                    if (c2335lzY.w() != 0) {
                        throw new GeneralSecurityException("Only version 0 keys are accepted");
                    }
                    com.quizlet.data.repository.metering.j jVar = new com.quizlet.data.repository.metering.j();
                    jVar.g(c2335lzY.z().g());
                    jVar.f();
                    jVar.h();
                    jVar.d = AbstractC2462ox.a(c2377my.e);
                    Pw pwI = jVar.i();
                    Iw iw2 = new Iw(false);
                    iw2.c = pwI;
                    iw2.a = C2883yp.f(c2335lzY.z().a());
                    iw2.b = c2377my.f;
                    return iw2.f();
                } catch (zzgzh unused3) {
                    throw new GeneralSecurityException("Parsing AesGcmKey failed");
                }
            case 15:
                if (!c2377my.a.equals("type.googleapis.com/google.crypto.tink.AesGcmSivKey")) {
                    throw new IllegalArgumentException("Wrong type URL in call to AesGcmSivProtoSerialization.parseKey");
                }
                try {
                    BA ba4 = c2377my.c;
                    IA ia4 = IA.a;
                    C2305lB c2305lB4 = C2305lB.c;
                    C2507pz c2507pzY = C2507pz.y(ba4, IA.b);
                    if (c2507pzY.w() != 0) {
                        throw new GeneralSecurityException("Only version 0 keys are accepted");
                    }
                    int iG = c2507pzY.z().g();
                    if (iG != 16 && iG != 32) {
                        throw new InvalidAlgorithmParameterException(String.format("Invalid key size %d; only 16-byte and 32-byte AES keys are supported", Integer.valueOf(iG)));
                    }
                    Sw sw = new Sw(iG, AbstractC2548qx.a(c2377my.e));
                    Iw iw3 = new Iw(false);
                    iw3.c = sw;
                    iw3.a = C2883yp.f(c2507pzY.z().a());
                    iw3.b = c2377my.f;
                    return iw3.g();
                } catch (zzgzh unused4) {
                    throw new GeneralSecurityException("Parsing AesGcmSivKey failed");
                }
            case 19:
                if (!c2377my.a.equals("type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key")) {
                    throw new IllegalArgumentException("Wrong type URL in call to ChaCha20Poly1305ProtoSerialization.parseKey");
                }
                try {
                    BA ba5 = c2377my.c;
                    IA ia5 = IA.a;
                    C2305lB c2305lB5 = C2305lB.c;
                    C2678tz c2678tzY = C2678tz.y(ba5, IA.b);
                    if (c2678tzY.w() == 0) {
                        return Tw.S(AbstractC2633sx.a(c2377my.e), C2883yp.f(c2678tzY.z().a()), c2377my.f);
                    }
                    throw new GeneralSecurityException("Only version 0 keys are accepted");
                } catch (zzgzh unused5) {
                    throw new GeneralSecurityException("Parsing ChaCha20Poly1305Key failed");
                }
            case EventType.AUDIO /* 23 */:
                if (!c2377my.a.equals("type.googleapis.com/google.crypto.tink.XAesGcmKey")) {
                    throw new IllegalArgumentException("Wrong type URL in call to XAesGcmProtoSerialization.parseKey");
                }
                try {
                    BA ba6 = c2377my.c;
                    IA ia6 = IA.a;
                    C2305lB c2305lB6 = C2305lB.c;
                    C1870bA c1870bAY = C1870bA.y(ba6, IA.b);
                    if (c1870bAY.w() != 0) {
                        throw new GeneralSecurityException("Only version 0 keys are accepted");
                    }
                    if (c1870bAY.A().g() == 32) {
                        return C2074fx.S(C2118gx.b(AbstractC2934zx.a(c2377my.e), c1870bAY.z().w()), C2883yp.f(c1870bAY.A().a()), c2377my.f);
                    }
                    throw new GeneralSecurityException("Only 32 byte key size is accepted");
                } catch (zzgzh unused6) {
                    throw new GeneralSecurityException("Parsing XAesGcmKey failed");
                }
            default:
                if (!c2377my.a.equals("type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key")) {
                    throw new IllegalArgumentException("Wrong type URL in call to XChaCha20Poly1305ProtoSerialization.parseKey");
                }
                try {
                    BA ba7 = c2377my.c;
                    IA ia7 = IA.a;
                    C2305lB c2305lB7 = C2305lB.c;
                    C2176iA c2176iAY = C2176iA.y(ba7, IA.b);
                    if (c2176iAY.w() == 0) {
                        return C2162hx.S(Ax.a(c2377my.e), C2883yp.f(c2176iAY.z().a()), c2377my.f);
                    }
                    throw new GeneralSecurityException("Only version 0 keys are accepted");
                } catch (zzgzh unused7) {
                    throw new GeneralSecurityException("Parsing XChaCha20Poly1305Key failed");
                }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1857ay
    public AbstractC2547qw g(C2420ny c2420ny) throws GeneralSecurityException {
        switch (this.a) {
            case 1:
                Gz gz = c2420ny.b;
                if (!gz.B().equals("type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey")) {
                    throw new IllegalArgumentException("Wrong type URL in call to AesCtrHmacAeadProtoSerialization.parseParameters: ".concat(String.valueOf(gz.B())));
                }
                try {
                    BA baA = gz.A();
                    IA ia = IA.a;
                    C2305lB c2305lB = C2305lB.c;
                    Xy xyX = Xy.x(baA, IA.b);
                    if (xyX.z().x() != 0) {
                        throw new GeneralSecurityException("Only version 0 keys are accepted");
                    }
                    C2084g6 c2084g6 = new C2084g6(6);
                    c2084g6.d(xyX.y().w());
                    c2084g6.h(xyX.z().w());
                    c2084g6.i(xyX.y().z().w());
                    c2084g6.l(xyX.z().B().w());
                    c2084g6.e = AbstractC2333lx.a(xyX.z().B().x());
                    c2084g6.f = AbstractC2333lx.b(gz.z());
                    return c2084g6.n();
                } catch (zzgzh e) {
                    throw new GeneralSecurityException("Parsing AesCtrHmacAeadParameters failed: ", e);
                }
            case 5:
                Gz gz2 = c2420ny.b;
                if (!gz2.B().equals("type.googleapis.com/google.crypto.tink.AesEaxKey")) {
                    throw new IllegalArgumentException("Wrong type URL in call to AesEaxProtoSerialization.parseParameters: ".concat(String.valueOf(gz2.B())));
                }
                try {
                    BA baA2 = gz2.A();
                    IA ia2 = IA.a;
                    C2305lB c2305lB2 = C2305lB.c;
                    C2164hz c2164hzY = C2164hz.y(baA2, IA.b);
                    com.quizlet.data.repository.explanations.textbook.a aVar = new com.quizlet.data.repository.explanations.textbook.a(4);
                    aVar.i(c2164hzY.w());
                    aVar.g(c2164hzY.z().w());
                    aVar.j();
                    aVar.d = AbstractC2376mx.a(gz2.z());
                    return aVar.l();
                } catch (zzgzh e2) {
                    throw new GeneralSecurityException("Parsing AesEaxParameters failed: ", e2);
                }
            case 9:
                Gz gz3 = c2420ny.b;
                if (!gz3.B().equals("type.googleapis.com/google.crypto.tink.AesGcmKey")) {
                    throw new IllegalArgumentException("Wrong type URL in call to AesGcmProtoSerialization.parseParameters: ".concat(String.valueOf(gz3.B())));
                }
                try {
                    BA baA3 = gz3.A();
                    IA ia3 = IA.a;
                    C2305lB c2305lB3 = C2305lB.c;
                    C2421nz c2421nzZ = C2421nz.z(baA3, IA.b);
                    if (c2421nzZ.x() != 0) {
                        throw new GeneralSecurityException("Only version 0 parameters are accepted");
                    }
                    com.quizlet.data.repository.metering.j jVar = new com.quizlet.data.repository.metering.j();
                    jVar.g(c2421nzZ.w());
                    jVar.f();
                    jVar.h();
                    jVar.d = AbstractC2462ox.a(gz3.z());
                    return jVar.i();
                } catch (zzgzh e3) {
                    throw new GeneralSecurityException("Parsing AesGcmParameters failed: ", e3);
                }
            case 13:
                Gz gz4 = c2420ny.b;
                if (!gz4.B().equals("type.googleapis.com/google.crypto.tink.AesGcmSivKey")) {
                    throw new IllegalArgumentException("Wrong type URL in call to AesGcmSivProtoSerialization.parseParameters: ".concat(String.valueOf(gz4.B())));
                }
                try {
                    BA baA4 = gz4.A();
                    IA ia4 = IA.a;
                    C2305lB c2305lB4 = C2305lB.c;
                    C2592rz c2592rzZ = C2592rz.z(baA4, IA.b);
                    if (c2592rzZ.x() != 0) {
                        throw new GeneralSecurityException("Only version 0 parameters are accepted");
                    }
                    int iW = c2592rzZ.w();
                    if (iW == 16 || iW == 32) {
                        return new Sw(iW, AbstractC2548qx.a(gz4.z()));
                    }
                    throw new InvalidAlgorithmParameterException(String.format("Invalid key size %d; only 16-byte and 32-byte AES keys are supported", Integer.valueOf(iW)));
                } catch (zzgzh e4) {
                    throw new GeneralSecurityException("Parsing AesGcmSivParameters failed: ", e4);
                }
            case 17:
                Gz gz5 = c2420ny.b;
                if (!gz5.B().equals("type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key")) {
                    throw new IllegalArgumentException("Wrong type URL in call to ChaCha20Poly1305ProtoSerialization.parseParameters: ".concat(String.valueOf(gz5.B())));
                }
                try {
                    BA baA5 = gz5.A();
                    IA ia5 = IA.a;
                    C2305lB c2305lB5 = C2305lB.c;
                    C2721uz.x(baA5, IA.b);
                    return new Vw(AbstractC2633sx.a(gz5.z()));
                } catch (zzgzh e5) {
                    throw new GeneralSecurityException("Parsing ChaCha20Poly1305Parameters failed: ", e5);
                }
            case 21:
                Gz gz6 = c2420ny.b;
                if (!gz6.B().equals("type.googleapis.com/google.crypto.tink.XAesGcmKey")) {
                    throw new IllegalArgumentException("Wrong type URL in call to XAesGcmProtoSerialization.parseParameters: ".concat(String.valueOf(gz6.B())));
                }
                try {
                    BA baA6 = gz6.A();
                    IA ia6 = IA.a;
                    C2305lB c2305lB6 = C2305lB.c;
                    C1957dA c1957dAY = C1957dA.y(baA6, IA.b);
                    if (c1957dAY.w() == 0) {
                        return C2118gx.b(AbstractC2934zx.a(gz6.z()), c1957dAY.z().w());
                    }
                    throw new GeneralSecurityException("Only version 0 parameters are accepted");
                } catch (zzgzh e6) {
                    throw new GeneralSecurityException("Parsing XAesGcmParameters failed: ", e6);
                }
            default:
                Gz gz7 = c2420ny.b;
                if (!gz7.B().equals("type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key")) {
                    throw new IllegalArgumentException("Wrong type URL in call to XChaCha20Poly1305ProtoSerialization.parseParameters: ".concat(String.valueOf(gz7.B())));
                }
                try {
                    BA baA7 = gz7.A();
                    IA ia7 = IA.a;
                    C2305lB c2305lB7 = C2305lB.c;
                    if (C2218jA.y(baA7, IA.b).w() == 0) {
                        return new C2247jx(Ax.a(gz7.z()));
                    }
                    throw new GeneralSecurityException("Only version 0 parameters are accepted");
                } catch (zzgzh e7) {
                    throw new GeneralSecurityException("Parsing XChaCha20Poly1305Parameters failed: ", e7);
                }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1987dy
    public C2420ny h(AbstractC2547qw abstractC2547qw) {
        switch (this.a) {
            case 0:
                Hw hw = (Hw) abstractC2547qw;
                Fz fzW = Gz.w();
                fzW.h("type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey");
                Wy wyW = Xy.w();
                C1858az c1858azX = C1901bz.x();
                C1945cz c1945czX = C1988dz.x();
                int i = hw.c;
                c1945czX.e();
                ((C1988dz) c1945czX.b).zzc = i;
                C1988dz c1988dz = (C1988dz) c1945czX.c();
                c1858azX.e();
                C1901bz.B((C1901bz) c1858azX.b, c1988dz);
                c1858azX.e();
                ((C1901bz) c1858azX.b).zze = hw.a;
                C1901bz c1901bz = (C1901bz) c1858azX.c();
                wyW.e();
                Xy.A((Xy) wyW.b, c1901bz);
                C2936zz c2936zzY = Az.y();
                Cz czC = AbstractC2333lx.c(hw);
                c2936zzY.e();
                Az.D((Az) c2936zzY.b, czC);
                c2936zzY.e();
                ((Az) c2936zzY.b).zze = hw.b;
                Az az = (Az) c2936zzY.c();
                wyW.e();
                Xy.B((Xy) wyW.b, az);
                fzW.i(((Xy) wyW.c()).b());
                fzW.g(AbstractC2333lx.d(hw.e));
                return C2420ny.a((Gz) fzW.c());
            case 4:
                Mw mw = (Mw) abstractC2547qw;
                Fz fzW2 = Gz.w();
                fzW2.h("type.googleapis.com/google.crypto.tink.AesEaxKey");
                C2120gz c2120gzX = C2164hz.x();
                C2206iz c2206izX = C2249jz.x();
                int i2 = mw.b;
                c2206izX.e();
                ((C2249jz) c2206izX.b).zzc = i2;
                C2249jz c2249jz = (C2249jz) c2206izX.c();
                c2120gzX.e();
                C2164hz.B((C2164hz) c2120gzX.b, c2249jz);
                c2120gzX.e();
                ((C2164hz) c2120gzX.b).zze = mw.a;
                fzW2.i(((C2164hz) c2120gzX.c()).b());
                fzW2.g(AbstractC2376mx.b(mw.c));
                return C2420ny.a((Gz) fzW2.c());
            case 8:
                Pw pw = (Pw) abstractC2547qw;
                Fz fzW3 = Gz.w();
                fzW3.h("type.googleapis.com/google.crypto.tink.AesGcmKey");
                C2378mz c2378mzY = C2421nz.y();
                int i3 = pw.a;
                c2378mzY.e();
                ((C2421nz) c2378mzY.b).zzc = i3;
                fzW3.i(((C2421nz) c2378mzY.c()).b());
                fzW3.g(AbstractC2462ox.b(pw.b));
                return C2420ny.a((Gz) fzW3.c());
            case 12:
                Sw sw = (Sw) abstractC2547qw;
                Fz fzW4 = Gz.w();
                fzW4.h("type.googleapis.com/google.crypto.tink.AesGcmSivKey");
                C2550qz c2550qzY = C2592rz.y();
                int i4 = sw.a;
                c2550qzY.e();
                ((C2592rz) c2550qzY.b).zzc = i4;
                fzW4.i(((C2592rz) c2550qzY.c()).b());
                fzW4.g(AbstractC2548qx.b(sw.b));
                return C2420ny.a((Gz) fzW4.c());
            case 16:
                Fz fzW5 = Gz.w();
                fzW5.h("type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key");
                fzW5.i(C2721uz.w().b());
                fzW5.g(AbstractC2633sx.b(((Vw) abstractC2547qw).a));
                return C2420ny.a((Gz) fzW5.c());
            case 20:
                C2118gx c2118gx = (C2118gx) abstractC2547qw;
                Fz fzW6 = Gz.w();
                fzW6.h("type.googleapis.com/google.crypto.tink.XAesGcmKey");
                C1913cA c1913cAX = C1957dA.x();
                C2044fA c2044fAX = C2088gA.x();
                int i5 = c2118gx.b;
                c2044fAX.e();
                ((C2088gA) c2044fAX.b).zzc = i5;
                C2088gA c2088gA = (C2088gA) c2044fAX.c();
                c1913cAX.e();
                C1957dA.A((C1957dA) c1913cAX.b, c2088gA);
                fzW6.i(((C1957dA) c1913cAX.c()).b());
                fzW6.g(AbstractC2934zx.b(c2118gx.a));
                return C2420ny.a((Gz) fzW6.c());
            default:
                Fz fzW7 = Gz.w();
                fzW7.h("type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key");
                fzW7.i(C2218jA.x().b());
                fzW7.g(Ax.b(((C2247jx) abstractC2547qw).a));
                return C2420ny.a((Gz) fzW7.c());
        }
    }

    @Override // com.google.android.gms.internal.ads.Jx
    public C2377my a(AbstractC2025es abstractC2025es) {
        switch (this.a) {
            case 2:
                Aw aw = (Aw) abstractC2025es;
                Uy uyX = Vy.x();
                Yy yyX = Zy.x();
                C1945cz c1945czX = C1988dz.x();
                int i = aw.c.c;
                c1945czX.e();
                ((C1988dz) c1945czX.b).zzc = i;
                C1988dz c1988dz = (C1988dz) c1945czX.c();
                yyX.e();
                Zy.C((Zy) yyX.b, c1988dz);
                byte[] bArrB = ((C2604sA) aw.d.b).b();
                C2905zA c2905zAW = BA.w(0, bArrB, bArrB.length);
                yyX.e();
                ((Zy) yyX.b).zzf = c2905zAW;
                Zy zy = (Zy) yyX.c();
                uyX.e();
                Vy.C((Vy) uyX.b, zy);
                C2850xz c2850xzX = C2893yz.x();
                Hw hw = aw.c;
                Cz czC = AbstractC2333lx.c(hw);
                c2850xzX.e();
                C2893yz.E((C2893yz) c2850xzX.b, czC);
                byte[] bArrB2 = ((C2604sA) aw.e.b).b();
                C2905zA c2905zAW2 = BA.w(0, bArrB2, bArrB2.length);
                c2850xzX.e();
                ((C2893yz) c2850xzX.b).zzf = c2905zAW2;
                C2893yz c2893yz = (C2893yz) c2850xzX.c();
                uyX.e();
                Vy.D((Vy) uyX.b, c2893yz);
                return C2377my.a("type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey", ((Vy) uyX.c()).b(), 2, AbstractC2333lx.d(hw.e), aw.g);
            case 6:
                Jw jw = (Jw) abstractC2025es;
                C2032ez c2032ezX = C2076fz.x();
                Mw mw = jw.c;
                C2206iz c2206izX = C2249jz.x();
                int i2 = mw.b;
                c2206izX.e();
                ((C2249jz) c2206izX.b).zzc = i2;
                C2249jz c2249jz = (C2249jz) c2206izX.c();
                c2032ezX.e();
                C2076fz.D((C2076fz) c2032ezX.b, c2249jz);
                byte[] bArrB3 = ((C2604sA) jw.d.b).b();
                C2905zA c2905zAW3 = BA.w(0, bArrB3, bArrB3.length);
                c2032ezX.e();
                ((C2076fz) c2032ezX.b).zzf = c2905zAW3;
                return C2377my.a("type.googleapis.com/google.crypto.tink.AesEaxKey", ((C2076fz) c2032ezX.c()).b(), 2, AbstractC2376mx.b(jw.c.c), jw.f);
            case 10:
                Nw nw = (Nw) abstractC2025es;
                C2292kz c2292kzX = C2335lz.x();
                byte[] bArrB4 = ((C2604sA) nw.d.b).b();
                C2905zA c2905zAW4 = BA.w(0, bArrB4, bArrB4.length);
                c2292kzX.e();
                ((C2335lz) c2292kzX.b).zzd = c2905zAW4;
                return C2377my.a("type.googleapis.com/google.crypto.tink.AesGcmKey", ((C2335lz) c2292kzX.c()).b(), 2, AbstractC2462ox.b(nw.c.b), nw.f);
            case 14:
                Qw qw = (Qw) abstractC2025es;
                C2464oz c2464ozX = C2507pz.x();
                byte[] bArrB5 = ((C2604sA) qw.d.b).b();
                C2905zA c2905zAW5 = BA.w(0, bArrB5, bArrB5.length);
                c2464ozX.e();
                ((C2507pz) c2464ozX.b).zzd = c2905zAW5;
                return C2377my.a("type.googleapis.com/google.crypto.tink.AesGcmSivKey", ((C2507pz) c2464ozX.c()).b(), 2, AbstractC2548qx.b(qw.c.b), qw.f);
            case 18:
                Tw tw = (Tw) abstractC2025es;
                C2635sz c2635szX = C2678tz.x();
                byte[] bArrB6 = ((C2604sA) tw.d.b).b();
                C2905zA c2905zAW6 = BA.w(0, bArrB6, bArrB6.length);
                c2635szX.e();
                ((C2678tz) c2635szX.b).zzd = c2905zAW6;
                return C2377my.a("type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key", ((C2678tz) c2635szX.c()).b(), 2, AbstractC2633sx.b(tw.c.a), tw.f);
            case EventType.WINDOW_STATE /* 22 */:
                C2074fx c2074fx = (C2074fx) abstractC2025es;
                C1826aA c1826aAX = C1870bA.x();
                byte[] bArrB7 = ((C2604sA) c2074fx.d.b).b();
                C2905zA c2905zAW7 = BA.w(0, bArrB7, bArrB7.length);
                c1826aAX.e();
                ((C1870bA) c1826aAX.b).zzf = c2905zAW7;
                C2044fA c2044fAX = C2088gA.x();
                C2118gx c2118gx = c2074fx.c;
                c2044fAX.e();
                ((C2088gA) c2044fAX.b).zzc = c2118gx.b;
                C2088gA c2088gA = (C2088gA) c2044fAX.c();
                c1826aAX.e();
                C1870bA.C((C1870bA) c1826aAX.b, c2088gA);
                return C2377my.a("type.googleapis.com/google.crypto.tink.XAesGcmKey", ((C1870bA) c1826aAX.c()).b(), 2, AbstractC2934zx.b(c2118gx.a), c2074fx.f);
            case EventType.CDN /* 26 */:
                C2162hx c2162hx = (C2162hx) abstractC2025es;
                C2132hA c2132hAX = C2176iA.x();
                byte[] bArrB8 = ((C2604sA) c2162hx.d.b).b();
                C2905zA c2905zAW8 = BA.w(0, bArrB8, bArrB8.length);
                c2132hAX.e();
                ((C2176iA) c2132hAX.b).zzd = c2905zAW8;
                return C2377my.a("type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key", ((C2176iA) c2132hAX.c()).b(), 2, Ax.b(c2162hx.c.a), c2162hx.f);
            default:
                C2377my c2377my = ((Nx) abstractC2025es).c;
                int i3 = Lx.b[AbstractC0147y.k(c2377my.d)];
                return c2377my;
        }
    }
}
