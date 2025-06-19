package com.google.firebase.perf.v1;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.protobuf.AbstractC4004a;
import com.google.protobuf.AbstractC4006b;
import com.google.protobuf.AbstractC4027v;
import com.google.protobuf.C4005a0;
import com.google.protobuf.C4007b0;
import com.google.protobuf.C4026u;
import com.google.protobuf.N;
import com.google.protobuf.X;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/* loaded from: classes2.dex */
public final class E extends AbstractC4027v {
    public static final int CLIENT_START_TIME_US_FIELD_NUMBER = 4;
    public static final int COUNTERS_FIELD_NUMBER = 6;
    public static final int CUSTOM_ATTRIBUTES_FIELD_NUMBER = 8;
    private static final E DEFAULT_INSTANCE;
    public static final int DURATION_US_FIELD_NUMBER = 5;
    public static final int IS_AUTO_FIELD_NUMBER = 2;
    public static final int NAME_FIELD_NUMBER = 1;
    private static volatile X PARSER = null;
    public static final int PERF_SESSIONS_FIELD_NUMBER = 9;
    public static final int SUBTRACES_FIELD_NUMBER = 7;
    private int bitField0_;
    private long clientStartTimeUs_;
    private N counters_;
    private N customAttributes_;
    private long durationUs_;
    private boolean isAuto_;
    private String name_;
    private com.google.protobuf.B perfSessions_;
    private com.google.protobuf.B subtraces_;

    static {
        E e = new E();
        DEFAULT_INSTANCE = e;
        AbstractC4027v.u(E.class, e);
    }

    public E() {
        N n = N.b;
        this.counters_ = n;
        this.customAttributes_ = n;
        this.name_ = "";
        C4005a0 c4005a0 = C4005a0.d;
        this.subtraces_ = c4005a0;
        this.perfSessions_ = c4005a0;
    }

    public static N A(E e) {
        N n = e.customAttributes_;
        if (!n.a) {
            e.customAttributes_ = n.e();
        }
        return e.customAttributes_;
    }

    public static void B(E e, z zVar) {
        e.getClass();
        com.google.protobuf.B b = e.perfSessions_;
        if (!((AbstractC4006b) b).a) {
            e.perfSessions_ = AbstractC4027v.r(b);
        }
        e.perfSessions_.add(zVar);
    }

    public static void C(E e, List list) {
        com.google.protobuf.B b = e.perfSessions_;
        if (!((AbstractC4006b) b).a) {
            e.perfSessions_ = AbstractC4027v.r(b);
        }
        AbstractC4004a.a(list, e.perfSessions_);
    }

    public static void D(E e, long j) {
        e.bitField0_ |= 4;
        e.clientStartTimeUs_ = j;
    }

    public static void E(E e, long j) {
        e.bitField0_ |= 8;
        e.durationUs_ = j;
    }

    public static E J() {
        return DEFAULT_INSTANCE;
    }

    public static B P() {
        return (B) DEFAULT_INSTANCE.k();
    }

    public static void w(E e, String str) {
        e.getClass();
        str.getClass();
        e.bitField0_ |= 1;
        e.name_ = str;
    }

    public static N x(E e) {
        N n = e.counters_;
        if (!n.a) {
            e.counters_ = n.e();
        }
        return e.counters_;
    }

    public static void y(E e, E e2) {
        e.getClass();
        e2.getClass();
        com.google.protobuf.B b = e.subtraces_;
        if (!((AbstractC4006b) b).a) {
            e.subtraces_ = AbstractC4027v.r(b);
        }
        e.subtraces_.add(e2);
    }

    public static void z(E e, ArrayList arrayList) {
        com.google.protobuf.B b = e.subtraces_;
        if (!((AbstractC4006b) b).a) {
            e.subtraces_ = AbstractC4027v.r(b);
        }
        AbstractC4004a.a(arrayList, e.subtraces_);
    }

    public final boolean F() {
        return this.customAttributes_.containsKey("Hosting_activity");
    }

    public final int G() {
        return this.counters_.size();
    }

    public final Map H() {
        return Collections.unmodifiableMap(this.counters_);
    }

    public final Map I() {
        return Collections.unmodifiableMap(this.customAttributes_);
    }

    public final long K() {
        return this.durationUs_;
    }

    public final String L() {
        return this.name_;
    }

    public final com.google.protobuf.B M() {
        return this.perfSessions_;
    }

    public final com.google.protobuf.B N() {
        return this.subtraces_;
    }

    public final boolean O() {
        return (this.bitField0_ & 4) != 0;
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
                return new C4007b0(DEFAULT_INSTANCE, "\u0001\b\u0000\u0001\u0001\t\b\u0002\u0002\u0000\u0001ဈ\u0000\u0002ဇ\u0001\u0004ဂ\u0002\u0005ဂ\u0003\u00062\u0007\u001b\b2\t\u001b", new Object[]{"bitField0_", "name_", "isAuto_", "clientStartTimeUs_", "durationUs_", "counters_", C.a, "subtraces_", E.class, "customAttributes_", D.a, "perfSessions_", z.class});
            case 3:
                return new E();
            case 4:
                return new B(DEFAULT_INSTANCE);
            case 5:
                return DEFAULT_INSTANCE;
            case 6:
                X x = PARSER;
                if (x != null) {
                    return x;
                }
                synchronized (E.class) {
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
