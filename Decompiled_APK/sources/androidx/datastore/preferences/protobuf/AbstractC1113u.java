package androidx.datastore.preferences.protobuf;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/* renamed from: androidx.datastore.preferences.protobuf.u, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC1113u extends AbstractC1094a {
    private static final int MEMOIZED_SERIALIZED_SIZE_MASK = Integer.MAX_VALUE;
    private static final int MUTABLE_FLAG_MASK = Integer.MIN_VALUE;
    static final int UNINITIALIZED_HASH_CODE = 0;
    static final int UNINITIALIZED_SERIALIZED_SIZE = Integer.MAX_VALUE;
    private static Map<Object, AbstractC1113u> defaultInstanceMap = new ConcurrentHashMap();
    private int memoizedSerializedSize;
    protected a0 unknownFields;

    public AbstractC1113u() {
        this.memoizedHashCode = 0;
        this.memoizedSerializedSize = -1;
        this.unknownFields = a0.f;
    }

    public static AbstractC1113u d(Class cls) throws ClassNotFoundException {
        AbstractC1113u abstractC1113u = defaultInstanceMap.get(cls);
        if (abstractC1113u == null) {
            try {
                Class.forName(cls.getName(), true, cls.getClassLoader());
                abstractC1113u = defaultInstanceMap.get(cls);
            } catch (ClassNotFoundException e) {
                throw new IllegalStateException("Class initialization cannot fail.", e);
            }
        }
        if (abstractC1113u != null) {
            return abstractC1113u;
        }
        AbstractC1113u abstractC1113u2 = (AbstractC1113u) ((AbstractC1113u) g0.d(cls)).c(6);
        if (abstractC1113u2 == null) {
            throw new IllegalStateException();
        }
        defaultInstanceMap.put(cls, abstractC1113u2);
        return abstractC1113u2;
    }

    public static Object e(Method method, AbstractC1094a abstractC1094a, Object... objArr) {
        try {
            return method.invoke(abstractC1094a, objArr);
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

    public static final boolean f(AbstractC1113u abstractC1113u, boolean z) {
        byte bByteValue = ((Byte) abstractC1113u.c(1)).byteValue();
        if (bByteValue == 1) {
            return true;
        }
        if (bByteValue == 0) {
            return false;
        }
        Q q = Q.c;
        q.getClass();
        boolean zC = q.a(abstractC1113u.getClass()).c(abstractC1113u);
        if (z) {
            abstractC1113u.c(2);
        }
        return zC;
    }

    public static void j(Class cls, AbstractC1113u abstractC1113u) {
        abstractC1113u.h();
        defaultInstanceMap.put(cls, abstractC1113u);
    }

    @Override // androidx.datastore.preferences.protobuf.AbstractC1094a
    public final int a(U u) {
        int iF;
        int iF2;
        if (g()) {
            if (u == null) {
                Q q = Q.c;
                q.getClass();
                iF2 = q.a(getClass()).f(this);
            } else {
                iF2 = u.f(this);
            }
            if (iF2 >= 0) {
                return iF2;
            }
            throw new IllegalStateException(android.support.v4.media.session.a.f(iF2, "serialized size must be non-negative, was "));
        }
        int i = this.memoizedSerializedSize;
        if ((i & SubsamplingScaleImageView.TILE_SIZE_AUTO) != Integer.MAX_VALUE) {
            return i & SubsamplingScaleImageView.TILE_SIZE_AUTO;
        }
        if (u == null) {
            Q q2 = Q.c;
            q2.getClass();
            iF = q2.a(getClass()).f(this);
        } else {
            iF = u.f(this);
        }
        k(iF);
        return iF;
    }

    @Override // androidx.datastore.preferences.protobuf.AbstractC1094a
    public final void b(C1104k c1104k) {
        Q q = Q.c;
        q.getClass();
        U uA = q.a(getClass());
        C c = c1104k.b;
        if (c == null) {
            c = new C(c1104k);
        }
        uA.e(this, c);
    }

    public abstract Object c(int i);

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        Q q = Q.c;
        q.getClass();
        return q.a(getClass()).h(this, (AbstractC1113u) obj);
    }

    public final boolean g() {
        return (this.memoizedSerializedSize & Integer.MIN_VALUE) != 0;
    }

    public final void h() {
        this.memoizedSerializedSize &= SubsamplingScaleImageView.TILE_SIZE_AUTO;
    }

    public final int hashCode() {
        if (g()) {
            Q q = Q.c;
            q.getClass();
            return q.a(getClass()).g(this);
        }
        if (this.memoizedHashCode == 0) {
            Q q2 = Q.c;
            q2.getClass();
            this.memoizedHashCode = q2.a(getClass()).g(this);
        }
        return this.memoizedHashCode;
    }

    public final AbstractC1113u i() {
        return (AbstractC1113u) c(4);
    }

    public final void k(int i) {
        if (i < 0) {
            throw new IllegalStateException(android.support.v4.media.session.a.f(i, "serialized size must be non-negative, was "));
        }
        this.memoizedSerializedSize = (i & SubsamplingScaleImageView.TILE_SIZE_AUTO) | (this.memoizedSerializedSize & Integer.MIN_VALUE);
    }

    public final String toString() {
        String string = super.toString();
        char[] cArr = J.a;
        StringBuilder sb = new StringBuilder();
        sb.append("# ");
        sb.append(string);
        J.c(this, sb, 0);
        return sb.toString();
    }
}
