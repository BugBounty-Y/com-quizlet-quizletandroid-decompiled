package com.google.android.gms.internal.ads;

import androidx.camera.camera2.internal.AbstractC0147y;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;

/* renamed from: com.google.android.gms.internal.ads.wy, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C2806wy implements InterfaceC2205iy, InterfaceC1987dy, InterfaceC1857ay, Jx, Hx, InterfaceC2001eB, Bt, Pk {
    public final /* synthetic */ int a;

    public /* synthetic */ C2806wy(int i) {
        this.a = i;
    }

    public static final VA e(long j, Object obj) {
        VA va = (VA) AbstractC2906zB.i(j, obj);
        if (((AbstractC2690uA) va).a) {
            return va;
        }
        int size = va.size();
        VA vaD = va.d(size == 0 ? 10 : size + size);
        AbstractC2906zB.n(j, obj, vaD);
        return vaD;
    }

    public static final C1871bB j(Object obj, Object obj2) {
        C1871bB c1871bBB = (C1871bB) obj;
        C1871bB c1871bB = (C1871bB) obj2;
        if (!c1871bB.isEmpty()) {
            if (!c1871bBB.a) {
                c1871bBB = c1871bBB.b();
            }
            c1871bBB.e();
            if (!c1871bB.isEmpty()) {
                c1871bBB.putAll(c1871bB);
            }
        }
        return c1871bBB;
    }

    public static String k(int i, byte[] bArr, int i2) {
        int i3;
        int length = bArr.length;
        if ((((length - i) - i2) | i | i2) < 0) {
            throw new ArrayIndexOutOfBoundsException(String.format("buffer length=%d, index=%d, size=%d", Integer.valueOf(length), Integer.valueOf(i), Integer.valueOf(i2)));
        }
        int i4 = i + i2;
        char[] cArr = new char[i2];
        int i5 = 0;
        while (i < i4) {
            byte b = bArr[i];
            if (b < 0) {
                break;
            }
            i++;
            cArr[i5] = (char) b;
            i5++;
        }
        int i6 = i5;
        while (i < i4) {
            int i7 = i + 1;
            byte b2 = bArr[i];
            if (b2 >= 0) {
                cArr[i6] = (char) b2;
                i6++;
                i = i7;
                while (i < i4) {
                    byte b3 = bArr[i];
                    if (b3 >= 0) {
                        i++;
                        cArr[i6] = (char) b3;
                        i6++;
                    }
                }
            } else {
                if (b2 < -32) {
                    if (i7 >= i4) {
                        throw new zzgzh("Protocol message had invalid UTF-8.");
                    }
                    i3 = i6 + 1;
                    i += 2;
                    AbstractC1981ds.v(b2, bArr[i7], cArr, i6);
                } else if (b2 < -16) {
                    if (i7 >= i4 - 1) {
                        throw new zzgzh("Protocol message had invalid UTF-8.");
                    }
                    i3 = i6 + 1;
                    int i8 = i + 2;
                    i += 3;
                    AbstractC1981ds.o(b2, bArr[i7], bArr[i8], cArr, i6);
                } else {
                    if (i7 >= i4 - 2) {
                        throw new zzgzh("Protocol message had invalid UTF-8.");
                    }
                    byte b4 = bArr[i7];
                    int i9 = i + 3;
                    byte b5 = bArr[i + 2];
                    i += 4;
                    AbstractC1981ds.d(b2, b4, b5, bArr[i9], cArr, i6);
                    i6 += 2;
                }
                i6 = i3;
            }
        }
        return new String(cArr, 0, i6);
    }

    public static final String l(ByteBuffer byteBuffer, int i, int i2) throws zzgzh {
        int i3;
        if ((((byteBuffer.limit() - i) - i2) | i | i2) < 0) {
            throw new ArrayIndexOutOfBoundsException(String.format("buffer limit=%d, index=%d, limit=%d", Integer.valueOf(byteBuffer.limit()), Integer.valueOf(i), Integer.valueOf(i2)));
        }
        int i4 = i + i2;
        char[] cArr = new char[i2];
        int i5 = 0;
        while (i < i4) {
            byte b = byteBuffer.get(i);
            if (b < 0) {
                break;
            }
            i++;
            cArr[i5] = (char) b;
            i5++;
        }
        int i6 = i5;
        while (i < i4) {
            int i7 = i + 1;
            byte b2 = byteBuffer.get(i);
            if (b2 >= 0) {
                cArr[i6] = (char) b2;
                i6++;
                i = i7;
                while (i < i4) {
                    byte b3 = byteBuffer.get(i);
                    if (b3 >= 0) {
                        i++;
                        cArr[i6] = (char) b3;
                        i6++;
                    }
                }
            } else {
                if (b2 < -32) {
                    if (i7 >= i4) {
                        throw new zzgzh("Protocol message had invalid UTF-8.");
                    }
                    i3 = i6 + 1;
                    i += 2;
                    AbstractC1981ds.v(b2, byteBuffer.get(i7), cArr, i6);
                } else if (b2 < -16) {
                    if (i7 >= i4 - 1) {
                        throw new zzgzh("Protocol message had invalid UTF-8.");
                    }
                    i3 = i6 + 1;
                    int i8 = i + 2;
                    i += 3;
                    AbstractC1981ds.o(b2, byteBuffer.get(i7), byteBuffer.get(i8), cArr, i6);
                } else {
                    if (i7 >= i4 - 2) {
                        throw new zzgzh("Protocol message had invalid UTF-8.");
                    }
                    byte b4 = byteBuffer.get(i7);
                    int i9 = i + 3;
                    byte b5 = byteBuffer.get(i + 2);
                    i += 4;
                    AbstractC1981ds.d(b2, b4, b5, byteBuffer.get(i9), cArr, i6);
                    i6 += 2;
                }
                i6 = i3;
            }
        }
        return new String(cArr, 0, i6);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2205iy, com.google.android.gms.internal.ads.Jx
    public C2377my a(AbstractC2025es abstractC2025es) {
        switch (this.a) {
            case 7:
                C2720uy c2720uy = (C2720uy) abstractC2025es;
                Oy oyX = Py.x();
                C2892yy c2892yy = c2720uy.c;
                Sy syX = Ty.x();
                int i = c2892yy.b;
                syX.e();
                ((Ty) syX.b).zzc = i;
                Ty ty = (Ty) syX.c();
                oyX.e();
                Py.D((Py) oyX.b, ty);
                byte[] bArrB = ((C2604sA) c2720uy.d.b).b();
                C2905zA c2905zAW = BA.w(0, bArrB, bArrB.length);
                oyX.e();
                ((Py) oyX.b).zze = c2905zAW;
                return C2377my.a("type.googleapis.com/google.crypto.tink.AesCmacKey", ((Py) oyX.c()).b(), 2, Ky.b(c2720uy.c.c), c2720uy.f);
            default:
                Ay ay = (Ay) abstractC2025es;
                C2850xz c2850xzX = C2893yz.x();
                Ey ey = ay.c;
                Bz bzY = Cz.y();
                int i2 = ey.b;
                bzY.e();
                ((Cz) bzY.b).zzd = i2;
                EnumC2764vz enumC2764vz = (EnumC2764vz) Ly.b.a(ey.d);
                bzY.e();
                ((Cz) bzY.b).zzc = enumC2764vz.a();
                Cz cz = (Cz) bzY.c();
                c2850xzX.e();
                C2893yz.E((C2893yz) c2850xzX.b, cz);
                byte[] bArrB2 = ((C2604sA) ay.d.b).b();
                C2905zA c2905zAW2 = BA.w(0, bArrB2, bArrB2.length);
                c2850xzX.e();
                ((C2893yz) c2850xzX.b).zzf = c2905zAW2;
                return C2377my.a("type.googleapis.com/google.crypto.tink.HmacKey", ((C2893yz) c2850xzX.c()).b(), 2, (Yz) Ly.a.a(ay.c.c), ay.f);
        }
    }

    @Override // com.google.android.gms.internal.ads.Pk
    /* renamed from: b */
    public void mo10b(Object obj) {
        WD wd = (WD) obj;
        switch (this.a) {
            case 27:
                int i = C2221jD.i1;
                wd.i(wd.g(), 14, new TD(11));
                break;
            case 28:
                int i2 = C2221jD.i1;
                wd.i(wd.l(), 22, new C2047fD(15));
                break;
            default:
                int i3 = C2221jD.i1;
                wd.i(wd.l(), 24, new TD(12));
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2001eB
    public C2391nB c(Class cls) {
        throw new IllegalStateException("This should never be called.");
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2001eB
    public boolean d(Class cls) {
        return false;
    }

    @Override // com.google.android.gms.internal.ads.Hx
    public AbstractC2025es f(C2377my c2377my) throws GeneralSecurityException {
        boolean z = false;
        switch (this.a) {
            case 8:
                if (!c2377my.a.equals("type.googleapis.com/google.crypto.tink.AesCmacKey")) {
                    throw new IllegalArgumentException("Wrong type URL in call to AesCmacProtoSerialization.parseKey");
                }
                try {
                    BA ba = c2377my.c;
                    IA ia = IA.a;
                    C2305lB c2305lB = C2305lB.c;
                    Py pyY = Py.y(ba, IA.b);
                    if (pyY.w() != 0) {
                        throw new GeneralSecurityException("Only version 0 keys are accepted");
                    }
                    Iw iw = new Iw();
                    iw.b(pyY.A().g());
                    iw.d(pyY.z().w());
                    iw.a = Ky.a(c2377my.e);
                    C2892yy c2892yyI = iw.i();
                    Iw iw2 = new Iw(z);
                    iw2.c = c2892yyI;
                    iw2.a = C2883yp.f(pyY.A().a());
                    iw2.b = c2377my.f;
                    return iw2.h();
                } catch (zzgzh | IllegalArgumentException unused) {
                    throw new GeneralSecurityException("Parsing AesCmacKey failed");
                }
            default:
                if (!c2377my.a.equals("type.googleapis.com/google.crypto.tink.HmacKey")) {
                    throw new IllegalArgumentException("Wrong type URL in call to HmacProtoSerialization.parseKey");
                }
                try {
                    BA ba2 = c2377my.c;
                    IA ia2 = IA.a;
                    C2305lB c2305lB2 = C2305lB.c;
                    C2893yz c2893yzZ = C2893yz.z(ba2, IA.b);
                    if (c2893yzZ.w() != 0) {
                        throw new GeneralSecurityException("Only version 0 keys are accepted");
                    }
                    com.quizlet.data.repository.studysetwithcreator.d dVar = new com.quizlet.data.repository.studysetwithcreator.d(4);
                    dVar.f(c2893yzZ.B().g());
                    dVar.g(c2893yzZ.A().w());
                    dVar.c = (Cy) Ly.b.b(c2893yzZ.A().x());
                    dVar.d = (Dy) Ly.a.b(c2377my.e);
                    Ey eyH = dVar.h();
                    Iw iw3 = new Iw(z);
                    iw3.c = eyH;
                    iw3.a = C2883yp.f(c2893yzZ.B().a());
                    iw3.b = c2377my.f;
                    return iw3.j();
                } catch (zzgzh | IllegalArgumentException unused2) {
                    throw new GeneralSecurityException("Parsing HmacKey failed");
                }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1857ay
    public AbstractC2547qw g(C2420ny c2420ny) throws GeneralSecurityException {
        switch (this.a) {
            case 6:
                Gz gz = c2420ny.b;
                if (!gz.B().equals("type.googleapis.com/google.crypto.tink.AesCmacKey")) {
                    throw new IllegalArgumentException("Wrong type URL in call to AesCmacProtoSerialization.parseParameters: ".concat(String.valueOf(gz.B())));
                }
                try {
                    BA baA = gz.A();
                    IA ia = IA.a;
                    C2305lB c2305lB = C2305lB.c;
                    Ry ryY = Ry.y(baA, IA.b);
                    Iw iw = new Iw();
                    iw.b(ryY.w());
                    iw.d(ryY.z().w());
                    iw.a = Ky.a(gz.z());
                    return iw.i();
                } catch (zzgzh e) {
                    throw new GeneralSecurityException("Parsing AesCmacParameters failed: ", e);
                }
            default:
                Gz gz2 = c2420ny.b;
                if (!gz2.B().equals("type.googleapis.com/google.crypto.tink.HmacKey")) {
                    throw new IllegalArgumentException("Wrong type URL in call to HmacProtoSerialization.parseParameters: ".concat(String.valueOf(gz2.B())));
                }
                try {
                    BA baA2 = gz2.A();
                    IA ia2 = IA.a;
                    C2305lB c2305lB2 = C2305lB.c;
                    Az azA = Az.A(baA2, IA.b);
                    if (azA.x() != 0) {
                        throw new GeneralSecurityException(android.support.v4.media.session.a.f(azA.x(), "Parsing HmacParameters failed: unknown Version "));
                    }
                    com.quizlet.data.repository.studysetwithcreator.d dVar = new com.quizlet.data.repository.studysetwithcreator.d(4);
                    dVar.f(azA.w());
                    dVar.g(azA.B().w());
                    dVar.c = (Cy) Ly.b.b(azA.B().x());
                    dVar.d = (Dy) Ly.a.b(gz2.z());
                    return dVar.h();
                } catch (zzgzh e2) {
                    throw new GeneralSecurityException("Parsing HmacParameters failed: ", e2);
                }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1987dy
    public C2420ny h(AbstractC2547qw abstractC2547qw) {
        switch (this.a) {
            case 5:
                C2892yy c2892yy = (C2892yy) abstractC2547qw;
                Fz fzW = Gz.w();
                fzW.h("type.googleapis.com/google.crypto.tink.AesCmacKey");
                Qy qyX = Ry.x();
                Sy syX = Ty.x();
                int i = c2892yy.b;
                syX.e();
                ((Ty) syX.b).zzc = i;
                Ty ty = (Ty) syX.c();
                qyX.e();
                Ry.B((Ry) qyX.b, ty);
                qyX.e();
                ((Ry) qyX.b).zzd = c2892yy.a;
                fzW.i(((Ry) qyX.c()).b());
                fzW.g(Ky.b(c2892yy.c));
                return C2420ny.a((Gz) fzW.c());
            default:
                Ey ey = (Ey) abstractC2547qw;
                Fz fzW2 = Gz.w();
                fzW2.h("type.googleapis.com/google.crypto.tink.HmacKey");
                C2936zz c2936zzY = Az.y();
                Bz bzY = Cz.y();
                int i2 = ey.b;
                bzY.e();
                ((Cz) bzY.b).zzd = i2;
                EnumC2764vz enumC2764vz = (EnumC2764vz) Ly.b.a(ey.d);
                bzY.e();
                ((Cz) bzY.b).zzc = enumC2764vz.a();
                Cz cz = (Cz) bzY.c();
                c2936zzY.e();
                Az.D((Az) c2936zzY.b, cz);
                c2936zzY.e();
                ((Az) c2936zzY.b).zze = ey.a;
                fzW2.i(((Az) c2936zzY.c()).b());
                fzW2.g((Yz) Ly.a.a(ey.c));
                return C2420ny.a((Gz) fzW2.c());
        }
    }

    public /* bridge */ Object i(String str, Provider provider) {
        switch (this.a) {
            case 13:
                return provider == null ? Cipher.getInstance(str) : Cipher.getInstance(str, provider);
            case 14:
                return provider == null ? KeyAgreement.getInstance(str) : KeyAgreement.getInstance(str, provider);
            case 15:
                return provider == null ? KeyFactory.getInstance(str) : KeyFactory.getInstance(str, provider);
            case 16:
                return provider == null ? KeyPairGenerator.getInstance(str) : KeyPairGenerator.getInstance(str, provider);
            case 17:
                return provider == null ? Mac.getInstance(str) : Mac.getInstance(str, provider);
            case 18:
                return provider == null ? MessageDigest.getInstance(str) : MessageDigest.getInstance(str, provider);
            default:
                return provider == null ? Signature.getInstance(str) : Signature.getInstance(str, provider);
        }
    }

    @Override // com.google.android.gms.internal.ads.Bt
    public Object zza() {
        return new UC();
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2205iy, com.google.android.gms.internal.ads.Jx
    public Object a(AbstractC2025es abstractC2025es) throws GeneralSecurityException {
        switch (this.a) {
            case 0:
                C2720uy c2720uy = (C2720uy) abstractC2025es;
                if (c2720uy.c.a == 32) {
                    return new C2561rA(c2720uy);
                }
                throw new GeneralSecurityException("AesCmacKey size wrong, must be 32 bytes");
            case 1:
                C2935zy c2935zy = new C2935zy();
                if (AbstractC1981ds.j(2)) {
                    return c2935zy;
                }
                throw new GeneralSecurityException("Can not use HMAC in FIPS-mode, as BoringCrypto module is not available.");
            case 2:
                return new C2561rA((Ay) abstractC2025es);
            default:
                Nx nx = (Nx) abstractC2025es;
                C2377my c2377my = nx.c;
                int i = Lx.b[AbstractC0147y.k(c2377my.d)];
                Kx kxA = Fx.d.a(InterfaceC2504pw.class, c2377my.a);
                Yz yz = Yz.RAW;
                AbstractC2025es abstractC2025esA = Xx.b.a(C2377my.a(kxA.a, c2377my.c, kxA.c, yz, null));
                Wx wx = Wx.b;
                int iOrdinal = c2377my.e.ordinal();
                C2377my c2377my2 = nx.c;
                if (iOrdinal == 1) {
                    Yx.b(c2377my2.f.intValue()).b();
                } else if (iOrdinal == 2) {
                    Yx.a(c2377my2.f.intValue()).b();
                } else if (iOrdinal == 3) {
                    Yx.a.b();
                } else {
                    if (iOrdinal != 4) {
                        throw new GeneralSecurityException("unknown output prefix type");
                    }
                    Yx.a(c2377my2.f.intValue()).b();
                }
                return new Iy();
        }
    }
}
