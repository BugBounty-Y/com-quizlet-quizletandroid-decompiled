package com.google.android.gms.internal.play_billing;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/* renamed from: com.google.android.gms.internal.play_billing.c1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3787c1 extends P0 {
    private static final Map zzb = new ConcurrentHashMap();
    protected B1 zzc;
    private int zzd;

    public AbstractC3787c1() {
        this.zza = 0;
        this.zzd = -1;
        this.zzc = B1.f;
    }

    public static AbstractC3787c1 h(Class cls) throws ClassNotFoundException {
        Map map = zzb;
        AbstractC3787c1 abstractC3787c1 = (AbstractC3787c1) map.get(cls);
        if (abstractC3787c1 == null) {
            try {
                Class.forName(cls.getName(), true, cls.getClassLoader());
                abstractC3787c1 = (AbstractC3787c1) map.get(cls);
            } catch (ClassNotFoundException e) {
                throw new IllegalStateException("Class initialization cannot fail.", e);
            }
        }
        if (abstractC3787c1 != null) {
            return abstractC3787c1;
        }
        AbstractC3787c1 abstractC3787c12 = (AbstractC3787c1) ((AbstractC3787c1) G1.f(cls)).d(6);
        if (abstractC3787c12 == null) {
            throw new IllegalStateException();
        }
        map.put(cls, abstractC3787c12);
        return abstractC3787c12;
    }

    public static Object i(Method method, P0 p0, Object... objArr) {
        try {
            return method.invoke(p0, objArr);
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

    public static void k(Class cls, AbstractC3787c1 abstractC3787c1) {
        abstractC3787c1.j();
        zzb.put(cls, abstractC3787c1);
    }

    public static final boolean m(AbstractC3787c1 abstractC3787c1, boolean z) {
        byte bByteValue = ((Byte) abstractC3787c1.d(1)).byteValue();
        if (bByteValue == 1) {
            return true;
        }
        if (bByteValue == 0) {
            return false;
        }
        boolean zC = C3843v1.c.a(abstractC3787c1.getClass()).c(abstractC3787c1);
        if (z) {
            abstractC3787c1.d(2);
        }
        return zC;
    }

    @Override // com.google.android.gms.internal.play_billing.P0
    public final int a(InterfaceC3852y1 interfaceC3852y1) {
        if (c()) {
            int iD = interfaceC3852y1.d(this);
            if (iD >= 0) {
                return iD;
            }
            throw new IllegalStateException(android.support.v4.media.session.a.f(iD, "serialized size must be non-negative, was "));
        }
        int i = this.zzd & SubsamplingScaleImageView.TILE_SIZE_AUTO;
        if (i != Integer.MAX_VALUE) {
            return i;
        }
        int iD2 = interfaceC3852y1.d(this);
        if (iD2 < 0) {
            throw new IllegalStateException(android.support.v4.media.session.a.f(iD2, "serialized size must be non-negative, was "));
        }
        this.zzd = (this.zzd & Integer.MIN_VALUE) | iD2;
        return iD2;
    }

    public final boolean c() {
        return (this.zzd & Integer.MIN_VALUE) != 0;
    }

    public abstract Object d(int i);

    public final int e() {
        if (c()) {
            int iD = C3843v1.c.a(getClass()).d(this);
            if (iD >= 0) {
                return iD;
            }
            throw new IllegalStateException(android.support.v4.media.session.a.f(iD, "serialized size must be non-negative, was "));
        }
        int i = this.zzd & SubsamplingScaleImageView.TILE_SIZE_AUTO;
        if (i != Integer.MAX_VALUE) {
            return i;
        }
        int iD2 = C3843v1.c.a(getClass()).d(this);
        if (iD2 < 0) {
            throw new IllegalStateException(android.support.v4.media.session.a.f(iD2, "serialized size must be non-negative, was "));
        }
        this.zzd = (this.zzd & Integer.MIN_VALUE) | iD2;
        return iD2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        return C3843v1.c.a(getClass()).g(this, (AbstractC3787c1) obj);
    }

    public final AbstractC3784b1 f() {
        return (AbstractC3784b1) d(5);
    }

    public final AbstractC3784b1 g() {
        AbstractC3784b1 abstractC3784b1 = (AbstractC3784b1) d(5);
        if (!abstractC3784b1.a.equals(this)) {
            if (!abstractC3784b1.b.c()) {
                AbstractC3787c1 abstractC3787c1 = (AbstractC3787c1) abstractC3784b1.a.d(4);
                C3843v1.c.a(abstractC3787c1.getClass()).b(abstractC3787c1, abstractC3784b1.b);
                abstractC3784b1.b = abstractC3787c1;
            }
            AbstractC3787c1 abstractC3787c12 = abstractC3784b1.b;
            C3843v1.c.a(abstractC3787c12.getClass()).b(abstractC3787c12, this);
        }
        return abstractC3784b1;
    }

    public final int hashCode() {
        if (c()) {
            return C3843v1.c.a(getClass()).f(this);
        }
        int i = this.zza;
        if (i != 0) {
            return i;
        }
        int iF = C3843v1.c.a(getClass()).f(this);
        this.zza = iF;
        return iF;
    }

    public final void j() {
        this.zzd &= SubsamplingScaleImageView.TILE_SIZE_AUTO;
    }

    public final void l() {
        this.zzd = (this.zzd & Integer.MIN_VALUE) | SubsamplingScaleImageView.TILE_SIZE_AUTO;
    }

    public final String toString() {
        String string = super.toString();
        char[] cArr = AbstractC3829q1.a;
        StringBuilder sb = new StringBuilder();
        sb.append("# ");
        sb.append(string);
        AbstractC3829q1.c(this, sb, 0);
        return sb.toString();
    }
}
