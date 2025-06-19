package com.quizlet.local.datastore.models.metering;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.protobuf.AbstractC4027v;
import com.google.protobuf.C4007b0;
import com.google.protobuf.C4026u;
import com.google.protobuf.X;

/* loaded from: classes3.dex */
public final class d extends AbstractC4027v {
    private static final d DEFAULT_INSTANCE;
    public static final int EVENTTYPE_FIELD_NUMBER = 3;
    public static final int NUMEVENTS_FIELD_NUMBER = 1;
    private static volatile X PARSER = null;
    public static final int REASON_FIELD_NUMBER = 6;
    public static final int RESOURCEID_FIELD_NUMBER = 4;
    public static final int THRESHOLD_FIELD_NUMBER = 2;
    public static final int USERID_FIELD_NUMBER = 5;
    private int eventType_;
    private int numEvents_;
    private int reason_;
    private long resourceId_;
    private int threshold_;
    private long userId_;

    static {
        d dVar = new d();
        DEFAULT_INSTANCE = dVar;
        AbstractC4027v.u(d.class, dVar);
    }

    public static void A(d dVar, int i) {
        dVar.threshold_ = i;
    }

    public static void B(d dVar, long j) {
        dVar.userId_ = j;
    }

    public static d C() {
        return DEFAULT_INSTANCE;
    }

    public static c J() {
        return (c) DEFAULT_INSTANCE.k();
    }

    public static void w(d dVar, int i) {
        dVar.eventType_ = i;
    }

    public static void x(d dVar, int i) {
        dVar.numEvents_ = i;
    }

    public static void y(d dVar, int i) {
        dVar.reason_ = i;
    }

    public static void z(d dVar, long j) {
        dVar.resourceId_ = j;
    }

    public final int D() {
        return this.eventType_;
    }

    public final int E() {
        return this.numEvents_;
    }

    public final int F() {
        return this.reason_;
    }

    public final long G() {
        return this.resourceId_;
    }

    public final int H() {
        return this.threshold_;
    }

    public final long I() {
        return this.userId_;
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
                return new C4007b0(DEFAULT_INSTANCE, "\u0000\u0006\u0000\u0000\u0001\u0006\u0006\u0000\u0000\u0000\u0001\u0004\u0002\u0004\u0003\u0004\u0004\u0002\u0005\u0002\u0006\u0004", new Object[]{"numEvents_", "threshold_", "eventType_", "resourceId_", "userId_", "reason_"});
            case 3:
                return new d();
            case 4:
                return new c(DEFAULT_INSTANCE);
            case 5:
                return DEFAULT_INSTANCE;
            case 6:
                X x = PARSER;
                if (x != null) {
                    return x;
                }
                synchronized (d.class) {
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
