package com.google.firebase.perf.v1;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.protobuf.AbstractC4027v;
import com.google.protobuf.C4007b0;
import com.google.protobuf.C4026u;
import com.google.protobuf.N;
import com.google.protobuf.X;

/* renamed from: com.google.firebase.perf.v1.g, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3977g extends AbstractC4027v {
    public static final int ANDROID_APP_INFO_FIELD_NUMBER = 3;
    public static final int APPLICATION_PROCESS_STATE_FIELD_NUMBER = 5;
    public static final int APP_INSTANCE_ID_FIELD_NUMBER = 2;
    public static final int CUSTOM_ATTRIBUTES_FIELD_NUMBER = 6;
    private static final C3977g DEFAULT_INSTANCE;
    public static final int GOOGLE_APP_ID_FIELD_NUMBER = 1;
    private static volatile X PARSER;
    private C3972b androidAppInfo_;
    private int applicationProcessState_;
    private int bitField0_;
    private N customAttributes_ = N.b;
    private String googleAppId_ = "";
    private String appInstanceId_ = "";

    static {
        C3977g c3977g = new C3977g();
        DEFAULT_INSTANCE = c3977g;
        AbstractC4027v.u(C3977g.class, c3977g);
    }

    public static void A(C3977g c3977g, C3972b c3972b) {
        c3977g.getClass();
        c3977g.androidAppInfo_ = c3972b;
        c3977g.bitField0_ |= 4;
    }

    public static C3977g C() {
        return DEFAULT_INSTANCE;
    }

    public static C3975e H() {
        return (C3975e) DEFAULT_INSTANCE.k();
    }

    public static void w(C3977g c3977g, String str) {
        c3977g.getClass();
        str.getClass();
        c3977g.bitField0_ |= 1;
        c3977g.googleAppId_ = str;
    }

    public static void x(C3977g c3977g, i iVar) {
        c3977g.getClass();
        c3977g.applicationProcessState_ = iVar.a;
        c3977g.bitField0_ |= 8;
    }

    public static N y(C3977g c3977g) {
        N n = c3977g.customAttributes_;
        if (!n.a) {
            c3977g.customAttributes_ = n.e();
        }
        return c3977g.customAttributes_;
    }

    public static void z(C3977g c3977g, String str) {
        c3977g.getClass();
        str.getClass();
        c3977g.bitField0_ |= 2;
        c3977g.appInstanceId_ = str;
    }

    public final C3972b B() {
        C3972b c3972b = this.androidAppInfo_;
        return c3972b == null ? C3972b.z() : c3972b;
    }

    public final boolean D() {
        return (this.bitField0_ & 4) != 0;
    }

    public final boolean E() {
        return (this.bitField0_ & 2) != 0;
    }

    public final boolean F() {
        return (this.bitField0_ & 8) != 0;
    }

    public final boolean G() {
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
                return new C4007b0(DEFAULT_INSTANCE, "\u0001\u0005\u0000\u0001\u0001\u0006\u0005\u0001\u0000\u0000\u0001ဈ\u0000\u0002ဈ\u0001\u0003ဉ\u0002\u0005᠌\u0003\u00062", new Object[]{"bitField0_", "googleAppId_", "appInstanceId_", "androidAppInfo_", "applicationProcessState_", C3978h.b, "customAttributes_", AbstractC3976f.a});
            case 3:
                return new C3977g();
            case 4:
                return new C3975e(DEFAULT_INSTANCE);
            case 5:
                return DEFAULT_INSTANCE;
            case 6:
                X x = PARSER;
                if (x != null) {
                    return x;
                }
                synchronized (C3977g.class) {
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
