package com.google.android.gms.internal.play_billing;

import com.google.android.gms.internal.ads.C2776wA;
import java.io.IOException;

/* loaded from: classes2.dex */
public final class K1 extends AbstractC3787c1 {
    private static final K1 zzb;
    private int zzd;
    private int zze = 0;
    private Object zzf;
    private int zzg;
    private O1 zzh;

    static {
        K1 k1 = new K1();
        zzb = k1;
        AbstractC3787c1.k(K1.class, k1);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v2, types: [com.google.android.gms.internal.play_billing.y1] */
    /* JADX WARN: Type inference failed for: r2v1, types: [com.google.android.gms.internal.play_billing.c1, java.lang.Object] */
    public static K1 n(byte[] bArr, W0 w0) throws zzhr {
        K1 k1 = zzb;
        int length = bArr.length;
        if (length != 0) {
            ?? r2 = (AbstractC3787c1) k1.d(4);
            try {
                ?? A = C3843v1.c.a(r2.getClass());
                C2776wA c2776wA = new C2776wA();
                w0.getClass();
                A.e(r2, bArr, 0, length, c2776wA);
                A.a(r2);
                k1 = r2;
            } catch (zzhr e) {
                throw e;
            } catch (zzji e2) {
                throw new zzhr(e2.getMessage());
            } catch (IOException e3) {
                if (e3.getCause() instanceof zzhr) {
                    throw ((zzhr) e3.getCause());
                }
                throw new zzhr(e3.getMessage(), e3);
            } catch (IndexOutOfBoundsException unused) {
                throw new zzhr("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
            }
        }
        if (k1 == null || AbstractC3787c1.m(k1, true)) {
            return k1;
        }
        throw new zzhr(new zzji().getMessage());
    }

    public static /* synthetic */ void o(K1 k1, O1 o1) {
        k1.zzh = o1;
        k1.zzd |= 2;
    }

    public static /* synthetic */ void p(K1 k1, Y1 y1) {
        k1.zzf = y1;
        k1.zze = 4;
    }

    public static /* synthetic */ void q(K1 k1, int i) {
        k1.zzg = i - 1;
        k1.zzd |= 1;
    }

    public static J1 r() {
        return (J1) zzb.f();
    }

    @Override // com.google.android.gms.internal.play_billing.AbstractC3787c1
    public final Object d(int i) {
        int i2 = i - 1;
        if (i2 == 0) {
            return (byte) 1;
        }
        if (i2 == 2) {
            return new C3849x1(zzb, "\u0004\u0003\u0001\u0001\u0001\u0004\u0003\u0000\u0000\u0000\u0001᠌\u0000\u0002ဉ\u0001\u0004<\u0000", new Object[]{"zzf", "zze", "zzd", "zzg", O0.c, "zzh", Y1.class});
        }
        if (i2 == 3) {
            return new K1();
        }
        if (i2 == 4) {
            return new J1(zzb);
        }
        if (i2 != 5) {
            return null;
        }
        return zzb;
    }
}
