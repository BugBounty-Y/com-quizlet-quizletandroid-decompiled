package com.google.firebase.perf.v1;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.protobuf.AbstractC4027v;
import com.google.protobuf.C4007b0;
import com.google.protobuf.C4026u;
import com.google.protobuf.X;

/* renamed from: com.google.firebase.perf.v1.d, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3974d extends AbstractC4027v {
    public static final int CLIENT_TIME_US_FIELD_NUMBER = 1;
    private static final C3974d DEFAULT_INSTANCE;
    private static volatile X PARSER = null;
    public static final int USED_APP_JAVA_HEAP_MEMORY_KB_FIELD_NUMBER = 2;
    private int bitField0_;
    private long clientTimeUs_;
    private int usedAppJavaHeapMemoryKb_;

    static {
        C3974d c3974d = new C3974d();
        DEFAULT_INSTANCE = c3974d;
        AbstractC4027v.u(C3974d.class, c3974d);
    }

    public static void w(C3974d c3974d, long j) {
        c3974d.bitField0_ |= 1;
        c3974d.clientTimeUs_ = j;
    }

    public static void x(C3974d c3974d, int i) {
        c3974d.bitField0_ |= 2;
        c3974d.usedAppJavaHeapMemoryKb_ = i;
    }

    public static C3973c y() {
        return (C3973c) DEFAULT_INSTANCE.k();
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
                return new C4007b0(DEFAULT_INSTANCE, "\u0001\u0002\u0000\u0001\u0001\u0002\u0002\u0000\u0000\u0000\u0001ဂ\u0000\u0002င\u0001", new Object[]{"bitField0_", "clientTimeUs_", "usedAppJavaHeapMemoryKb_"});
            case 3:
                return new C3974d();
            case 4:
                return new C3973c(DEFAULT_INSTANCE);
            case 5:
                return DEFAULT_INSTANCE;
            case 6:
                X x = PARSER;
                if (x != null) {
                    return x;
                }
                synchronized (C3974d.class) {
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
