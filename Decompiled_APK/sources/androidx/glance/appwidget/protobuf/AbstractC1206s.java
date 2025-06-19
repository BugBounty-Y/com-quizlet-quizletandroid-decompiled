package androidx.glance.appwidget.protobuf;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/* renamed from: androidx.glance.appwidget.protobuf.s, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC1206s extends AbstractC1189a {
    private static final int MEMOIZED_SERIALIZED_SIZE_MASK = Integer.MAX_VALUE;
    private static final int MUTABLE_FLAG_MASK = Integer.MIN_VALUE;
    static final int UNINITIALIZED_HASH_CODE = 0;
    static final int UNINITIALIZED_SERIALIZED_SIZE = Integer.MAX_VALUE;
    private static Map<Object, AbstractC1206s> defaultInstanceMap = new ConcurrentHashMap();
    private int memoizedSerializedSize;
    protected S unknownFields;

    public AbstractC1206s() {
        this.memoizedHashCode = 0;
        this.memoizedSerializedSize = -1;
        this.unknownFields = S.f;
    }

    public static AbstractC1206s c(Class cls) throws ClassNotFoundException {
        AbstractC1206s abstractC1206s = defaultInstanceMap.get(cls);
        if (abstractC1206s == null) {
            try {
                Class.forName(cls.getName(), true, cls.getClassLoader());
                abstractC1206s = defaultInstanceMap.get(cls);
            } catch (ClassNotFoundException e) {
                throw new IllegalStateException("Class initialization cannot fail.", e);
            }
        }
        if (abstractC1206s != null) {
            return abstractC1206s;
        }
        AbstractC1206s abstractC1206s2 = (AbstractC1206s) ((AbstractC1206s) Y.d(cls)).b(6);
        if (abstractC1206s2 == null) {
            throw new IllegalStateException();
        }
        defaultInstanceMap.put(cls, abstractC1206s2);
        return abstractC1206s2;
    }

    public static Object d(Method method, AbstractC1189a abstractC1189a, Object... objArr) {
        try {
            return method.invoke(abstractC1189a, objArr);
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

    public static final boolean e(AbstractC1206s abstractC1206s, boolean z) {
        byte bByteValue = ((Byte) abstractC1206s.b(1)).byteValue();
        if (bByteValue == 1) {
            return true;
        }
        if (bByteValue == 0) {
            return false;
        }
        L l = L.c;
        l.getClass();
        boolean zC = l.a(abstractC1206s.getClass()).c(abstractC1206s);
        if (z) {
            abstractC1206s.b(2);
        }
        return zC;
    }

    public static void i(Class cls, AbstractC1206s abstractC1206s) {
        abstractC1206s.g();
        defaultInstanceMap.put(cls, abstractC1206s);
    }

    @Override // androidx.glance.appwidget.protobuf.AbstractC1189a
    public final int a(O o) {
        int iE;
        int iE2;
        if (f()) {
            if (o == null) {
                L l = L.c;
                l.getClass();
                iE2 = l.a(getClass()).e(this);
            } else {
                iE2 = o.e(this);
            }
            if (iE2 >= 0) {
                return iE2;
            }
            throw new IllegalStateException(android.support.v4.media.session.a.f(iE2, "serialized size must be non-negative, was "));
        }
        int i = this.memoizedSerializedSize;
        if ((i & SubsamplingScaleImageView.TILE_SIZE_AUTO) != Integer.MAX_VALUE) {
            return i & SubsamplingScaleImageView.TILE_SIZE_AUTO;
        }
        if (o == null) {
            L l2 = L.c;
            l2.getClass();
            iE = l2.a(getClass()).e(this);
        } else {
            iE = o.e(this);
        }
        j(iE);
        return iE;
    }

    public abstract Object b(int i);

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        L l = L.c;
        l.getClass();
        return l.a(getClass()).i(this, (AbstractC1206s) obj);
    }

    public final boolean f() {
        return (this.memoizedSerializedSize & Integer.MIN_VALUE) != 0;
    }

    public final void g() {
        this.memoizedSerializedSize &= SubsamplingScaleImageView.TILE_SIZE_AUTO;
    }

    public final AbstractC1206s h() {
        return (AbstractC1206s) b(4);
    }

    public final int hashCode() {
        if (f()) {
            L l = L.c;
            l.getClass();
            return l.a(getClass()).g(this);
        }
        if (this.memoizedHashCode == 0) {
            L l2 = L.c;
            l2.getClass();
            this.memoizedHashCode = l2.a(getClass()).g(this);
        }
        return this.memoizedHashCode;
    }

    public final void j(int i) {
        if (i < 0) {
            throw new IllegalStateException(android.support.v4.media.session.a.f(i, "serialized size must be non-negative, was "));
        }
        this.memoizedSerializedSize = (i & SubsamplingScaleImageView.TILE_SIZE_AUTO) | (this.memoizedSerializedSize & Integer.MIN_VALUE);
    }

    public final String toString() {
        String string = super.toString();
        char[] cArr = F.a;
        StringBuilder sb = new StringBuilder();
        sb.append("# ");
        sb.append(string);
        F.c(this, sb, 0);
        return sb.toString();
    }
}
