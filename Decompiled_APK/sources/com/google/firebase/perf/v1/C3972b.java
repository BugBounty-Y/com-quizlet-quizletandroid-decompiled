package com.google.firebase.perf.v1;

import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.protobuf.AbstractC4027v;
import com.google.protobuf.C4007b0;
import com.google.protobuf.C4026u;
import com.google.protobuf.X;

/* renamed from: com.google.firebase.perf.v1.b, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3972b extends AbstractC4027v {
    private static final C3972b DEFAULT_INSTANCE;
    public static final int PACKAGE_NAME_FIELD_NUMBER = 1;
    private static volatile X PARSER = null;
    public static final int SDK_VERSION_FIELD_NUMBER = 2;
    public static final int VERSION_NAME_FIELD_NUMBER = 3;
    private int bitField0_;
    private String packageName_ = "";
    private String sdkVersion_ = "";
    private String versionName_ = "";

    static {
        C3972b c3972b = new C3972b();
        DEFAULT_INSTANCE = c3972b;
        AbstractC4027v.u(C3972b.class, c3972b);
    }

    public static C3971a C() {
        return (C3971a) DEFAULT_INSTANCE.k();
    }

    public static void w(C3972b c3972b, String str) {
        c3972b.getClass();
        str.getClass();
        c3972b.bitField0_ |= 1;
        c3972b.packageName_ = str;
    }

    public static void x(C3972b c3972b) {
        c3972b.getClass();
        c3972b.bitField0_ |= 2;
        c3972b.sdkVersion_ = "21.0.5";
    }

    public static void y(C3972b c3972b, String str) {
        c3972b.getClass();
        c3972b.bitField0_ |= 4;
        c3972b.versionName_ = str;
    }

    public static C3972b z() {
        return DEFAULT_INSTANCE;
    }

    public final boolean A() {
        return (this.bitField0_ & 1) != 0;
    }

    public final boolean B() {
        return (this.bitField0_ & 2) != 0;
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
                return new C4007b0(DEFAULT_INSTANCE, "\u0001\u0003\u0000\u0001\u0001\u0003\u0003\u0000\u0000\u0000\u0001ဈ\u0000\u0002ဈ\u0001\u0003ဈ\u0002", new Object[]{"bitField0_", "packageName_", "sdkVersion_", "versionName_"});
            case 3:
                return new C3972b();
            case 4:
                return new C3971a(DEFAULT_INSTANCE);
            case 5:
                return DEFAULT_INSTANCE;
            case 6:
                X x = PARSER;
                if (x != null) {
                    return x;
                }
                synchronized (C3972b.class) {
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
