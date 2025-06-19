package com.google.firebase.perf.v1;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.protobuf.AbstractC4006b;
import com.google.protobuf.AbstractC4027v;
import com.google.protobuf.C4005a0;
import com.google.protobuf.C4007b0;
import com.google.protobuf.C4026u;
import com.google.protobuf.X;

/* loaded from: classes2.dex */
public final class o extends AbstractC4027v {
    public static final int ANDROID_MEMORY_READINGS_FIELD_NUMBER = 4;
    public static final int CPU_METRIC_READINGS_FIELD_NUMBER = 2;
    private static final o DEFAULT_INSTANCE;
    public static final int GAUGE_METADATA_FIELD_NUMBER = 3;
    private static volatile X PARSER = null;
    public static final int SESSION_ID_FIELD_NUMBER = 1;
    private com.google.protobuf.B androidMemoryReadings_;
    private int bitField0_;
    private com.google.protobuf.B cpuMetricReadings_;
    private m gaugeMetadata_;
    private String sessionId_ = "";

    static {
        o oVar = new o();
        DEFAULT_INSTANCE = oVar;
        AbstractC4027v.u(o.class, oVar);
    }

    public o() {
        C4005a0 c4005a0 = C4005a0.d;
        this.cpuMetricReadings_ = c4005a0;
        this.androidMemoryReadings_ = c4005a0;
    }

    public static o C() {
        return DEFAULT_INSTANCE;
    }

    public static n G() {
        return (n) DEFAULT_INSTANCE.k();
    }

    public static void w(o oVar, String str) {
        oVar.getClass();
        str.getClass();
        oVar.bitField0_ |= 1;
        oVar.sessionId_ = str;
    }

    public static void x(o oVar, C3974d c3974d) {
        oVar.getClass();
        c3974d.getClass();
        com.google.protobuf.B b = oVar.androidMemoryReadings_;
        if (!((AbstractC4006b) b).a) {
            oVar.androidMemoryReadings_ = AbstractC4027v.r(b);
        }
        oVar.androidMemoryReadings_.add(c3974d);
    }

    public static void y(o oVar, m mVar) {
        oVar.getClass();
        mVar.getClass();
        oVar.gaugeMetadata_ = mVar;
        oVar.bitField0_ |= 2;
    }

    public static void z(o oVar, k kVar) {
        oVar.getClass();
        kVar.getClass();
        com.google.protobuf.B b = oVar.cpuMetricReadings_;
        if (!((AbstractC4006b) b).a) {
            oVar.cpuMetricReadings_ = AbstractC4027v.r(b);
        }
        oVar.cpuMetricReadings_.add(kVar);
    }

    public final int A() {
        return this.androidMemoryReadings_.size();
    }

    public final int B() {
        return this.cpuMetricReadings_.size();
    }

    public final m D() {
        m mVar = this.gaugeMetadata_;
        return mVar == null ? m.z() : mVar;
    }

    public final boolean E() {
        return (this.bitField0_ & 2) != 0;
    }

    public final boolean F() {
        return (this.bitField0_ & 1) != 0;
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
                return new C4007b0(DEFAULT_INSTANCE, "\u0001\u0004\u0000\u0001\u0001\u0004\u0004\u0000\u0002\u0000\u0001ဈ\u0000\u0002\u001b\u0003ဉ\u0001\u0004\u001b", new Object[]{"bitField0_", "sessionId_", "cpuMetricReadings_", k.class, "gaugeMetadata_", "androidMemoryReadings_", C3974d.class});
            case 3:
                return new o();
            case 4:
                return new n(DEFAULT_INSTANCE);
            case 5:
                return DEFAULT_INSTANCE;
            case 6:
                X x = PARSER;
                if (x != null) {
                    return x;
                }
                synchronized (o.class) {
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
