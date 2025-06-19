package com.google.firebase.perf.v1;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.protobuf.AbstractC4027v;
import com.google.protobuf.C4007b0;
import com.google.protobuf.C4026u;
import com.google.protobuf.X;

/* loaded from: classes2.dex */
public final class v extends AbstractC4027v implements w {
    public static final int APPLICATION_INFO_FIELD_NUMBER = 1;
    private static final v DEFAULT_INSTANCE;
    public static final int GAUGE_METRIC_FIELD_NUMBER = 4;
    public static final int NETWORK_REQUEST_METRIC_FIELD_NUMBER = 3;
    private static volatile X PARSER = null;
    public static final int TRACE_METRIC_FIELD_NUMBER = 2;
    public static final int TRANSPORT_INFO_FIELD_NUMBER = 5;
    private C3977g applicationInfo_;
    private int bitField0_;
    private o gaugeMetric_;
    private t networkRequestMetric_;
    private E traceMetric_;
    private H transportInfo_;

    static {
        v vVar = new v();
        DEFAULT_INSTANCE = vVar;
        AbstractC4027v.u(v.class, vVar);
    }

    public static u C() {
        return (u) DEFAULT_INSTANCE.k();
    }

    public static void w(v vVar, C3977g c3977g) {
        vVar.getClass();
        vVar.applicationInfo_ = c3977g;
        vVar.bitField0_ |= 1;
    }

    public static void x(v vVar, o oVar) {
        vVar.getClass();
        vVar.gaugeMetric_ = oVar;
        vVar.bitField0_ |= 8;
    }

    public static void y(v vVar, E e) {
        vVar.getClass();
        vVar.traceMetric_ = e;
        vVar.bitField0_ |= 2;
    }

    public static void z(v vVar, t tVar) {
        vVar.getClass();
        vVar.networkRequestMetric_ = tVar;
        vVar.bitField0_ |= 4;
    }

    public final C3977g A() {
        C3977g c3977g = this.applicationInfo_;
        return c3977g == null ? C3977g.C() : c3977g;
    }

    public final boolean B() {
        return (this.bitField0_ & 1) != 0;
    }

    @Override // com.google.firebase.perf.v1.w
    public final boolean b() {
        return (this.bitField0_ & 8) != 0;
    }

    @Override // com.google.firebase.perf.v1.w
    public final boolean c() {
        return (this.bitField0_ & 2) != 0;
    }

    @Override // com.google.firebase.perf.v1.w
    public final E d() {
        E e = this.traceMetric_;
        return e == null ? E.J() : e;
    }

    @Override // com.google.firebase.perf.v1.w
    public final boolean e() {
        return (this.bitField0_ & 4) != 0;
    }

    @Override // com.google.firebase.perf.v1.w
    public final t f() {
        t tVar = this.networkRequestMetric_;
        return tVar == null ? t.K() : tVar;
    }

    @Override // com.google.firebase.perf.v1.w
    public final o g() {
        o oVar = this.gaugeMetric_;
        return oVar == null ? o.C() : oVar;
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
                return new C4007b0(DEFAULT_INSTANCE, "\u0001\u0005\u0000\u0001\u0001\u0005\u0005\u0000\u0000\u0000\u0001ဉ\u0000\u0002ဉ\u0001\u0003ဉ\u0002\u0004ဉ\u0003\u0005ဉ\u0004", new Object[]{"bitField0_", "applicationInfo_", "traceMetric_", "networkRequestMetric_", "gaugeMetric_", "transportInfo_"});
            case 3:
                return new v();
            case 4:
                return new u(DEFAULT_INSTANCE);
            case 5:
                return DEFAULT_INSTANCE;
            case 6:
                X x = PARSER;
                if (x != null) {
                    return x;
                }
                synchronized (v.class) {
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
