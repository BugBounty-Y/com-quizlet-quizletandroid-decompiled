package com.google.firebase.perf.v1;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.protobuf.AbstractC4006b;
import com.google.protobuf.AbstractC4027v;
import com.google.protobuf.C4007b0;
import com.google.protobuf.C4026u;
import com.google.protobuf.C4028w;
import com.google.protobuf.InterfaceC4031z;
import com.google.protobuf.X;
import java.util.Arrays;
import java.util.RandomAccess;

/* loaded from: classes2.dex */
public final class z extends AbstractC4027v {
    private static final z DEFAULT_INSTANCE;
    private static volatile X PARSER = null;
    public static final int SESSION_ID_FIELD_NUMBER = 1;
    public static final int SESSION_VERBOSITY_FIELD_NUMBER = 2;
    private static final com.google.protobuf.A sessionVerbosity_converter_ = new x();
    private int bitField0_;
    private String sessionId_ = "";
    private InterfaceC4031z sessionVerbosity_ = C4028w.d;

    static {
        z zVar = new z();
        DEFAULT_INSTANCE = zVar;
        AbstractC4027v.u(z.class, zVar);
    }

    public static y A() {
        return (y) DEFAULT_INSTANCE.k();
    }

    public static void w(z zVar, String str) {
        zVar.getClass();
        str.getClass();
        zVar.bitField0_ |= 1;
        zVar.sessionId_ = str;
    }

    public static void x(z zVar) {
        zVar.getClass();
        RandomAccess randomAccess = zVar.sessionVerbosity_;
        if (!((AbstractC4006b) randomAccess).a) {
            C4028w c4028w = (C4028w) randomAccess;
            int i = c4028w.c;
            int i2 = i == 0 ? 10 : i * 2;
            if (i2 < i) {
                throw new IllegalArgumentException();
            }
            zVar.sessionVerbosity_ = new C4028w(Arrays.copyOf(c4028w.b, i2), c4028w.c, true);
        }
        ((C4028w) zVar.sessionVerbosity_).b(1);
    }

    @Override // com.google.protobuf.AbstractC4027v
    public final Object l(int i) {
        X c4026u;
        switch (AbstractC0147y.k(i)) {
            case 0:
                return (byte) 1;
            case 1:
                return null;
            case 2:
                return new C4007b0(DEFAULT_INSTANCE, "\u0001\u0002\u0000\u0001\u0001\u0002\u0002\u0000\u0001\u0000\u0001ဈ\u0000\u0002ࠞ", new Object[]{"bitField0_", "sessionId_", "sessionVerbosity_", C3978h.e});
            case 3:
                return new z();
            case 4:
                return new y(DEFAULT_INSTANCE);
            case 5:
                return DEFAULT_INSTANCE;
            case 6:
                X x = PARSER;
                if (x != null) {
                    return x;
                }
                synchronized (z.class) {
                    try {
                        c4026u = PARSER;
                        if (c4026u == null) {
                            c4026u = new C4026u();
                            PARSER = c4026u;
                        }
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                return c4026u;
            default:
                throw new UnsupportedOperationException();
        }
    }

    public final A y() {
        int iE = ((C4028w) this.sessionVerbosity_).e(0);
        A a = A.SESSION_VERBOSITY_NONE;
        A a2 = iE != 0 ? iE != 1 ? null : A.GAUGES_AND_SYSTEM_EVENTS : a;
        return a2 == null ? a : a2;
    }

    public final int z() {
        return ((C4028w) this.sessionVerbosity_).size();
    }
}
