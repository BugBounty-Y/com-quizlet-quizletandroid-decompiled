package com.google.protobuf;

import androidx.core.view.AbstractC1047f0;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/* renamed from: com.google.protobuf.v, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC4027v extends AbstractC4004a {
    private static final int MEMOIZED_SERIALIZED_SIZE_MASK = Integer.MAX_VALUE;
    private static final int MUTABLE_FLAG_MASK = Integer.MIN_VALUE;
    static final int UNINITIALIZED_HASH_CODE = 0;
    static final int UNINITIALIZED_SERIALIZED_SIZE = Integer.MAX_VALUE;
    private static Map<Object, AbstractC4027v> defaultInstanceMap = new ConcurrentHashMap();
    private int memoizedSerializedSize;
    protected k0 unknownFields;

    public AbstractC4027v() {
        this.memoizedHashCode = 0;
        this.memoizedSerializedSize = -1;
        this.unknownFields = k0.f;
    }

    public static AbstractC4027v m(Class cls) throws ClassNotFoundException {
        AbstractC4027v abstractC4027v = defaultInstanceMap.get(cls);
        if (abstractC4027v == null) {
            try {
                Class.forName(cls.getName(), true, cls.getClassLoader());
                abstractC4027v = defaultInstanceMap.get(cls);
            } catch (ClassNotFoundException e) {
                throw new IllegalStateException("Class initialization cannot fail.", e);
            }
        }
        if (abstractC4027v != null) {
            return abstractC4027v;
        }
        AbstractC4027v abstractC4027v2 = (AbstractC4027v) ((AbstractC4027v) t0.b(cls)).l(6);
        if (abstractC4027v2 == null) {
            throw new IllegalStateException();
        }
        defaultInstanceMap.put(cls, abstractC4027v2);
        return abstractC4027v2;
    }

    public static Object n(Method method, AbstractC4004a abstractC4004a, Object... objArr) {
        try {
            return method.invoke(abstractC4004a, objArr);
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

    public static final boolean o(AbstractC4027v abstractC4027v, boolean z) {
        byte bByteValue = ((Byte) abstractC4027v.l(1)).byteValue();
        if (bByteValue == 1) {
            return true;
        }
        if (bByteValue == 0) {
            return false;
        }
        Z z2 = Z.c;
        z2.getClass();
        boolean zC = z2.a(abstractC4027v.getClass()).c(abstractC4027v);
        if (z) {
            abstractC4027v.l(2);
        }
        return zC;
    }

    public static B r(B b) {
        int size = b.size();
        return b.q(size == 0 ? 10 : size * 2);
    }

    public static AbstractC4027v t(AbstractC4027v abstractC4027v, InputStream inputStream) throws InvalidProtocolBufferException {
        AbstractC1047f0 c4014h;
        if (inputStream == null) {
            byte[] bArr = C.b;
            int length = bArr.length;
            c4014h = new C4013g(bArr, 0, length, false);
            try {
                c4014h.i(length);
            } catch (InvalidProtocolBufferException e) {
                throw new IllegalArgumentException(e);
            }
        } else {
            c4014h = new C4014h(inputStream);
        }
        C4020n c4020nA = C4020n.a();
        AbstractC4027v abstractC4027vS = abstractC4027v.s();
        try {
            Z z = Z.c;
            z.getClass();
            InterfaceC4009c0 interfaceC4009c0A = z.a(abstractC4027vS.getClass());
            C4015i c4015i = (C4015i) c4014h.b;
            if (c4015i == null) {
                c4015i = new C4015i(c4014h);
            }
            interfaceC4009c0A.f(abstractC4027vS, c4015i, c4020nA);
            interfaceC4009c0A.b(abstractC4027vS);
            if (o(abstractC4027vS, true)) {
                return abstractC4027vS;
            }
            throw new InvalidProtocolBufferException(new UninitializedMessageException().getMessage());
        } catch (InvalidProtocolBufferException e2) {
            if (e2.a) {
                throw new InvalidProtocolBufferException(e2.getMessage(), e2);
            }
            throw e2;
        } catch (UninitializedMessageException e3) {
            throw new InvalidProtocolBufferException(e3.getMessage());
        } catch (IOException e4) {
            if (e4.getCause() instanceof InvalidProtocolBufferException) {
                throw ((InvalidProtocolBufferException) e4.getCause());
            }
            throw new InvalidProtocolBufferException(e4.getMessage(), e4);
        } catch (RuntimeException e5) {
            if (e5.getCause() instanceof InvalidProtocolBufferException) {
                throw ((InvalidProtocolBufferException) e5.getCause());
            }
            throw e5;
        }
    }

    public static void u(Class cls, AbstractC4027v abstractC4027v) {
        abstractC4027v.q();
        defaultInstanceMap.put(cls, abstractC4027v);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        Z z = Z.c;
        z.getClass();
        return z.a(getClass()).i(this, (AbstractC4027v) obj);
    }

    @Override // com.google.protobuf.AbstractC4004a
    public final int h(InterfaceC4009c0 interfaceC4009c0) {
        int iH;
        int iH2;
        if (p()) {
            if (interfaceC4009c0 == null) {
                Z z = Z.c;
                z.getClass();
                iH2 = z.a(getClass()).h(this);
            } else {
                iH2 = interfaceC4009c0.h(this);
            }
            if (iH2 >= 0) {
                return iH2;
            }
            throw new IllegalStateException(android.support.v4.media.session.a.f(iH2, "serialized size must be non-negative, was "));
        }
        int i = this.memoizedSerializedSize;
        if ((i & SubsamplingScaleImageView.TILE_SIZE_AUTO) != Integer.MAX_VALUE) {
            return i & SubsamplingScaleImageView.TILE_SIZE_AUTO;
        }
        if (interfaceC4009c0 == null) {
            Z z2 = Z.c;
            z2.getClass();
            iH = z2.a(getClass()).h(this);
        } else {
            iH = interfaceC4009c0.h(this);
        }
        v(iH);
        return iH;
    }

    public final int hashCode() {
        if (p()) {
            Z z = Z.c;
            z.getClass();
            return z.a(getClass()).g(this);
        }
        if (this.memoizedHashCode == 0) {
            Z z2 = Z.c;
            z2.getClass();
            this.memoizedHashCode = z2.a(getClass()).g(this);
        }
        return this.memoizedHashCode;
    }

    @Override // com.google.protobuf.AbstractC4004a
    public final void i(AbstractC4018l abstractC4018l) {
        Z z = Z.c;
        z.getClass();
        InterfaceC4009c0 interfaceC4009c0A = z.a(getClass());
        K k = abstractC4018l.c;
        if (k == null) {
            k = new K(abstractC4018l);
        }
        interfaceC4009c0A.e(this, k);
    }

    public final AbstractC4025t k() {
        return (AbstractC4025t) l(5);
    }

    public abstract Object l(int i);

    public final boolean p() {
        return (this.memoizedSerializedSize & Integer.MIN_VALUE) != 0;
    }

    public final void q() {
        this.memoizedSerializedSize &= SubsamplingScaleImageView.TILE_SIZE_AUTO;
    }

    public final AbstractC4027v s() {
        return (AbstractC4027v) l(4);
    }

    public final String toString() {
        String string = super.toString();
        char[] cArr = S.a;
        StringBuilder sb = new StringBuilder();
        sb.append("# ");
        sb.append(string);
        S.c(this, sb, 0);
        return sb.toString();
    }

    public final void v(int i) {
        if (i < 0) {
            throw new IllegalStateException(android.support.v4.media.session.a.f(i, "serialized size must be non-negative, was "));
        }
        this.memoizedSerializedSize = (i & SubsamplingScaleImageView.TILE_SIZE_AUTO) | (this.memoizedSerializedSize & Integer.MIN_VALUE);
    }
}
