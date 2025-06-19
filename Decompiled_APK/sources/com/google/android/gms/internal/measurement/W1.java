package com.google.android.gms.internal.measurement;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/* loaded from: classes2.dex */
public abstract class W1 extends J1 {
    private static final Map zzb = new ConcurrentHashMap();
    protected C3079x2 zzc;
    private int zzd;

    public W1() {
        this.zza = 0;
        this.zzd = -1;
        this.zzc = C3079x2.f;
    }

    public static W1 g(Class cls) throws ClassNotFoundException {
        Map map = zzb;
        W1 w1 = (W1) map.get(cls);
        if (w1 == null) {
            try {
                Class.forName(cls.getName(), true, cls.getClassLoader());
                w1 = (W1) map.get(cls);
            } catch (ClassNotFoundException e) {
                throw new IllegalStateException("Class initialization cannot fail.", e);
            }
        }
        if (w1 != null) {
            return w1;
        }
        W1 w12 = (W1) ((W1) C2.f(cls)).m(6);
        if (w12 == null) {
            throw new IllegalStateException();
        }
        map.put(cls, w12);
        return w12;
    }

    public static Object h(Method method, J1 j1, Object... objArr) {
        try {
            return method.invoke(j1, objArr);
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

    public static void j(Class cls, W1 w1) {
        w1.i();
        zzb.put(cls, w1);
    }

    @Override // com.google.android.gms.internal.measurement.J1
    public final int a(InterfaceC3069v2 interfaceC3069v2) {
        if (l()) {
            int iE = interfaceC3069v2.e(this);
            if (iE >= 0) {
                return iE;
            }
            throw new IllegalStateException(android.support.v4.media.session.a.f(iE, "serialized size must be non-negative, was "));
        }
        int i = this.zzd & SubsamplingScaleImageView.TILE_SIZE_AUTO;
        if (i != Integer.MAX_VALUE) {
            return i;
        }
        int iE2 = interfaceC3069v2.e(this);
        if (iE2 < 0) {
            throw new IllegalStateException(android.support.v4.media.session.a.f(iE2, "serialized size must be non-negative, was "));
        }
        this.zzd = (this.zzd & Integer.MIN_VALUE) | iE2;
        return iE2;
    }

    public final int d() {
        if (l()) {
            int iE = C3054s2.c.a(getClass()).e(this);
            if (iE >= 0) {
                return iE;
            }
            throw new IllegalStateException(android.support.v4.media.session.a.f(iE, "serialized size must be non-negative, was "));
        }
        int i = this.zzd & SubsamplingScaleImageView.TILE_SIZE_AUTO;
        if (i != Integer.MAX_VALUE) {
            return i;
        }
        int iE2 = C3054s2.c.a(getClass()).e(this);
        if (iE2 < 0) {
            throw new IllegalStateException(android.support.v4.media.session.a.f(iE2, "serialized size must be non-negative, was "));
        }
        this.zzd = (this.zzd & Integer.MIN_VALUE) | iE2;
        return iE2;
    }

    public final V1 e() {
        return (V1) m(5);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        return C3054s2.c.a(getClass()).g(this, (W1) obj);
    }

    public final V1 f() {
        V1 v1 = (V1) m(5);
        v1.d(this);
        return v1;
    }

    public final int hashCode() {
        if (l()) {
            return C3054s2.c.a(getClass()).f(this);
        }
        int i = this.zza;
        if (i != 0) {
            return i;
        }
        int iF = C3054s2.c.a(getClass()).f(this);
        this.zza = iF;
        return iF;
    }

    public final void i() {
        this.zzd &= SubsamplingScaleImageView.TILE_SIZE_AUTO;
    }

    public final void k() {
        this.zzd = (this.zzd & Integer.MIN_VALUE) | SubsamplingScaleImageView.TILE_SIZE_AUTO;
    }

    public final boolean l() {
        return (this.zzd & Integer.MIN_VALUE) != 0;
    }

    public abstract Object m(int i);

    public final String toString() {
        String string = super.toString();
        char[] cArr = AbstractC3030n2.a;
        StringBuilder sb = new StringBuilder();
        sb.append("# ");
        sb.append(string);
        AbstractC3030n2.c(this, sb, 0);
        return sb.toString();
    }
}
