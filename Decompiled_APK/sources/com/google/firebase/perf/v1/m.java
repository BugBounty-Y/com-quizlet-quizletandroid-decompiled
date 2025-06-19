package com.google.firebase.perf.v1;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.protobuf.AbstractC4027v;
import com.google.protobuf.C4007b0;
import com.google.protobuf.C4026u;
import com.google.protobuf.X;

/* loaded from: classes2.dex */
public final class m extends AbstractC4027v {
    public static final int CPU_CLOCK_RATE_KHZ_FIELD_NUMBER = 2;
    public static final int CPU_PROCESSOR_COUNT_FIELD_NUMBER = 6;
    private static final m DEFAULT_INSTANCE;
    public static final int DEVICE_RAM_SIZE_KB_FIELD_NUMBER = 3;
    public static final int MAX_APP_JAVA_HEAP_MEMORY_KB_FIELD_NUMBER = 4;
    public static final int MAX_ENCOURAGED_APP_JAVA_HEAP_MEMORY_KB_FIELD_NUMBER = 5;
    private static volatile X PARSER = null;
    public static final int PROCESS_NAME_FIELD_NUMBER = 1;
    private int bitField0_;
    private int cpuClockRateKhz_;
    private int cpuProcessorCount_;
    private int deviceRamSizeKb_;
    private int maxAppJavaHeapMemoryKb_;
    private int maxEncouragedAppJavaHeapMemoryKb_;
    private String processName_ = "";

    static {
        m mVar = new m();
        DEFAULT_INSTANCE = mVar;
        AbstractC4027v.u(m.class, mVar);
    }

    public static l B() {
        return (l) DEFAULT_INSTANCE.k();
    }

    public static void w(m mVar, int i) {
        mVar.bitField0_ |= 16;
        mVar.maxAppJavaHeapMemoryKb_ = i;
    }

    public static void x(m mVar, int i) {
        mVar.bitField0_ |= 32;
        mVar.maxEncouragedAppJavaHeapMemoryKb_ = i;
    }

    public static void y(m mVar, int i) {
        mVar.bitField0_ |= 8;
        mVar.deviceRamSizeKb_ = i;
    }

    public static m z() {
        return DEFAULT_INSTANCE;
    }

    public final boolean A() {
        return (this.bitField0_ & 16) != 0;
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
                return new C4007b0(DEFAULT_INSTANCE, "\u0001\u0006\u0000\u0001\u0001\u0006\u0006\u0000\u0000\u0000\u0001ဈ\u0000\u0002င\u0001\u0003င\u0003\u0004င\u0004\u0005င\u0005\u0006င\u0002", new Object[]{"bitField0_", "processName_", "cpuClockRateKhz_", "deviceRamSizeKb_", "maxAppJavaHeapMemoryKb_", "maxEncouragedAppJavaHeapMemoryKb_", "cpuProcessorCount_"});
            case 3:
                return new m();
            case 4:
                return new l(DEFAULT_INSTANCE);
            case 5:
                return DEFAULT_INSTANCE;
            case 6:
                X x = PARSER;
                if (x != null) {
                    return x;
                }
                synchronized (m.class) {
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
