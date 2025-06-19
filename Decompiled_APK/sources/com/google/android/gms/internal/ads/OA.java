package com.google.android.gms.internal.ads;

import androidx.core.view.AbstractC1047f0;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/* loaded from: classes2.dex */
public abstract class OA extends AbstractC2647tA {
    private static final int zza = Integer.MIN_VALUE;
    private static final int zzb = Integer.MAX_VALUE;
    private static Map<Class<?>, OA> zzc = new ConcurrentHashMap();
    static final int zzr = Integer.MAX_VALUE;
    static final int zzs = 0;
    private int zzd;
    protected C2691uB zzt;

    public OA() {
        this.zzq = 0;
        this.zzd = -1;
        this.zzt = C2691uB.f;
    }

    public static Object i(Method method, AbstractC2647tA abstractC2647tA, Object... objArr) {
        try {
            return method.invoke(abstractC2647tA, objArr);
        } catch (IllegalAccessException e) {
            throw new RuntimeException("Couldn't use Java reflection to implement protocol message reflection.", e);
        } catch (InvocationTargetException e2) {
            Throwable cause = e2.getCause();
            if (cause instanceof RuntimeException) {
                throw ((RuntimeException) cause);
            }
            if (cause instanceof Error) {
                throw ((Error) cause);
            }
            throw new RuntimeException("Unexpected exception thrown by generated accessor method.", cause);
        }
    }

    public static void k(Class cls, OA oa) {
        oa.j();
        zzc.put(cls, oa);
    }

    public static OA m(Class cls) throws ClassNotFoundException {
        OA oa = zzc.get(cls);
        if (oa == null) {
            try {
                Class.forName(cls.getName(), true, cls.getClassLoader());
                oa = zzc.get(cls);
            } catch (ClassNotFoundException e) {
                throw new IllegalStateException("Class initialization cannot fail.", e);
            }
        }
        if (oa != null) {
            return oa;
        }
        OA oa2 = (OA) ((OA) AbstractC2906zB.h(cls)).s(6, null);
        if (oa2 == null) {
            throw new IllegalStateException();
        }
        zzc.put(cls, oa2);
        return oa2;
    }

    public static OA o(OA oa, BA ba, IA ia) {
        AbstractC1047f0 abstractC1047f0O = ba.o();
        OA oaP = p(oa, abstractC1047f0O, ia);
        abstractC1047f0O.h0();
        t(oaP);
        return oaP;
    }

    public static OA p(OA oa, AbstractC1047f0 abstractC1047f0, IA ia) {
        OA oaN = oa.n();
        try {
            InterfaceC2562rB interfaceC2562rBA = C2305lB.c.a(oaN.getClass());
            androidx.compose.runtime.changelist.K k = (androidx.compose.runtime.changelist.K) abstractC1047f0.b;
            if (k == null) {
                k = new androidx.compose.runtime.changelist.K(abstractC1047f0);
            }
            interfaceC2562rBA.i(oaN, k, ia);
            interfaceC2562rBA.a(oaN);
            return oaN;
        } catch (zzgzh e) {
            if (e.a) {
                throw new zzgzh(e.getMessage(), e);
            }
            throw e;
        } catch (zzhbh e2) {
            throw new zzgzh(e2.getMessage());
        } catch (IOException e3) {
            if (e3.getCause() instanceof zzgzh) {
                throw ((zzgzh) e3.getCause());
            }
            throw new zzgzh(e3.getMessage(), e3);
        } catch (RuntimeException e4) {
            if (e4.getCause() instanceof zzgzh) {
                throw ((zzgzh) e4.getCause());
            }
            throw e4;
        }
    }

    public static void t(OA oa) {
        if (oa != null && !v(oa, true)) {
            throw new zzgzh(new zzhbh().getMessage());
        }
    }

    public static OA u(OA oa, byte[] bArr, int i, IA ia) throws zzgzh {
        if (i == 0) {
            return oa;
        }
        OA oaN = oa.n();
        try {
            InterfaceC2562rB interfaceC2562rBA = C2305lB.c.a(oaN.getClass());
            interfaceC2562rBA.c(oaN, bArr, 0, i, new C2776wA(ia));
            interfaceC2562rBA.a(oaN);
            return oaN;
        } catch (zzgzh e) {
            if (e.a) {
                throw new zzgzh(e.getMessage(), e);
            }
            throw e;
        } catch (zzhbh e2) {
            throw new zzgzh(e2.getMessage());
        } catch (IOException e3) {
            if (e3.getCause() instanceof zzgzh) {
                throw ((zzgzh) e3.getCause());
            }
            throw new zzgzh(e3.getMessage(), e3);
        } catch (IndexOutOfBoundsException unused) {
            throw new zzgzh("While parsing a protocol message, the input ended unexpectedly in the middle of a field.  This could mean either that the input has been truncated or that an embedded message misreported its own length.");
        }
    }

    public static final boolean v(OA oa, boolean z) {
        byte bByteValue = ((Byte) oa.s(1, null)).byteValue();
        if (bByteValue == 1) {
            return true;
        }
        if (bByteValue == 0) {
            return false;
        }
        boolean zD = C2305lB.c.a(oa.getClass()).d(oa);
        if (z) {
            oa.s(2, true == zD ? oa : null);
        }
        return zD;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2647tA
    public final int a(InterfaceC2562rB interfaceC2562rB) {
        int iG;
        int iG2;
        if (r()) {
            if (interfaceC2562rB == null) {
                iG2 = C2305lB.c.a(getClass()).g(this);
            } else {
                iG2 = interfaceC2562rB.g(this);
            }
            if (iG2 >= 0) {
                return iG2;
            }
            throw new IllegalStateException(android.support.v4.media.session.a.f(iG2, "serialized size must be non-negative, was "));
        }
        int i = this.zzd;
        if ((i & SubsamplingScaleImageView.TILE_SIZE_AUTO) != Integer.MAX_VALUE) {
            return i & SubsamplingScaleImageView.TILE_SIZE_AUTO;
        }
        if (interfaceC2562rB == null) {
            iG = C2305lB.c.a(getClass()).g(this);
        } else {
            iG = interfaceC2562rB.g(this);
        }
        f(iG);
        return iG;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        return C2305lB.c.a(getClass()).h(this, (OA) obj);
    }

    public final void f(int i) {
        if (i < 0) {
            throw new IllegalStateException(android.support.v4.media.session.a.f(i, "serialized size must be non-negative, was "));
        }
        this.zzd = i | (this.zzd & Integer.MIN_VALUE);
    }

    public final MA g() {
        return (MA) s(5, null);
    }

    public final InterfaceC2219jB h() {
        return (InterfaceC2219jB) s(7, null);
    }

    public final int hashCode() {
        if (r()) {
            return C2305lB.c.a(getClass()).f(this);
        }
        if (this.zzq == 0) {
            this.zzq = C2305lB.c.a(getClass()).f(this);
        }
        return this.zzq;
    }

    public final void j() {
        this.zzd &= SubsamplingScaleImageView.TILE_SIZE_AUTO;
    }

    public final MA l() {
        MA ma = (MA) s(5, null);
        if (ma.a.equals(this)) {
            return ma;
        }
        ma.e();
        OA oa = ma.b;
        C2305lB.c.a(oa.getClass()).b(oa, this);
        return ma;
    }

    public final OA n() {
        return (OA) s(4, null);
    }

    public final void q(HA ha) {
        InterfaceC2562rB interfaceC2562rBA = C2305lB.c.a(getClass());
        C2586rt c2586rt = ha.b;
        if (c2586rt == null) {
            c2586rt = new C2586rt(ha);
        }
        interfaceC2562rBA.e(this, c2586rt);
    }

    public final boolean r() {
        return (this.zzd & Integer.MIN_VALUE) != 0;
    }

    public abstract Object s(int i, OA oa);

    public final String toString() {
        String string = super.toString();
        char[] cArr = AbstractC2045fB.a;
        StringBuilder sb = new StringBuilder();
        sb.append("# ");
        sb.append(string);
        AbstractC2045fB.c(this, sb, 0);
        return sb.toString();
    }
}
