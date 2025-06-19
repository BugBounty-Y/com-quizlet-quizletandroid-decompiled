package com.google.firebase.perf.v1;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.protobuf.AbstractC4027v;
import com.google.protobuf.C4007b0;
import com.google.protobuf.C4026u;
import com.google.protobuf.X;

/* loaded from: classes2.dex */
public final class k extends AbstractC4027v {
    public static final int CLIENT_TIME_US_FIELD_NUMBER = 1;
    private static final k DEFAULT_INSTANCE;
    private static volatile X PARSER = null;
    public static final int SYSTEM_TIME_US_FIELD_NUMBER = 3;
    public static final int USER_TIME_US_FIELD_NUMBER = 2;
    private int bitField0_;
    private long clientTimeUs_;
    private long systemTimeUs_;
    private long userTimeUs_;

    static {
        k kVar = new k();
        DEFAULT_INSTANCE = kVar;
        AbstractC4027v.u(k.class, kVar);
    }

    public static void w(k kVar, long j) {
        kVar.bitField0_ |= 1;
        kVar.clientTimeUs_ = j;
    }

    public static void x(k kVar, long j) {
        kVar.bitField0_ |= 2;
        kVar.userTimeUs_ = j;
    }

    public static void y(k kVar, long j) {
        kVar.bitField0_ |= 4;
        kVar.systemTimeUs_ = j;
    }

    public static j z() {
        return (j) DEFAULT_INSTANCE.k();
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
                return new C4007b0(DEFAULT_INSTANCE, "\u0001\u0003\u0000\u0001\u0001\u0003\u0003\u0000\u0000\u0000\u0001ဂ\u0000\u0002ဂ\u0001\u0003ဂ\u0002", new Object[]{"bitField0_", "clientTimeUs_", "userTimeUs_", "systemTimeUs_"});
            case 3:
                return new k();
            case 4:
                return new j(DEFAULT_INSTANCE);
            case 5:
                return DEFAULT_INSTANCE;
            case 6:
                X x = PARSER;
                if (x != null) {
                    return x;
                }
                synchronized (k.class) {
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
}
