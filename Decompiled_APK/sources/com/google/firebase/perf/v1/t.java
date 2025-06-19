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
import java.util.List;

/* loaded from: classes2.dex */
public final class t extends AbstractC4027v {
    public static final int CLIENT_START_TIME_US_FIELD_NUMBER = 7;
    public static final int CUSTOM_ATTRIBUTES_FIELD_NUMBER = 12;
    private static final t DEFAULT_INSTANCE;
    public static final int HTTP_METHOD_FIELD_NUMBER = 2;
    public static final int HTTP_RESPONSE_CODE_FIELD_NUMBER = 5;
    public static final int NETWORK_CLIENT_ERROR_REASON_FIELD_NUMBER = 11;
    private static volatile X PARSER = null;
    public static final int PERF_SESSIONS_FIELD_NUMBER = 13;
    public static final int REQUEST_PAYLOAD_BYTES_FIELD_NUMBER = 3;
    public static final int RESPONSE_CONTENT_TYPE_FIELD_NUMBER = 6;
    public static final int RESPONSE_PAYLOAD_BYTES_FIELD_NUMBER = 4;
    public static final int TIME_TO_REQUEST_COMPLETED_US_FIELD_NUMBER = 8;
    public static final int TIME_TO_RESPONSE_COMPLETED_US_FIELD_NUMBER = 10;
    public static final int TIME_TO_RESPONSE_INITIATED_US_FIELD_NUMBER = 9;
    public static final int URL_FIELD_NUMBER = 1;
    private int bitField0_;
    private long clientStartTimeUs_;
    private int httpMethod_;
    private int httpResponseCode_;
    private int networkClientErrorReason_;
    private long requestPayloadBytes_;
    private long responsePayloadBytes_;
    private long timeToRequestCompletedUs_;
    private long timeToResponseCompletedUs_;
    private long timeToResponseInitiatedUs_;
    private N customAttributes_ = N.b;
    private String url_ = "";
    private String responseContentType_ = "";
    private com.google.protobuf.B perfSessions_ = C4005a0.d;

    static {
        t tVar = new t();
        DEFAULT_INSTANCE = tVar;
        AbstractC4027v.u(t.class, tVar);
    }

    public static void A(t tVar) {
        tVar.bitField0_ &= -65;
        tVar.responseContentType_ = DEFAULT_INSTANCE.responseContentType_;
    }

    public static void B(t tVar, long j) {
        tVar.bitField0_ |= 128;
        tVar.clientStartTimeUs_ = j;
    }

    public static void C(t tVar, long j) {
        tVar.bitField0_ |= 256;
        tVar.timeToRequestCompletedUs_ = j;
    }

    public static void D(t tVar, long j) {
        tVar.bitField0_ |= com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH;
        tVar.timeToResponseInitiatedUs_ = j;
    }

    public static void E(t tVar, long j) {
        tVar.bitField0_ |= 1024;
        tVar.timeToResponseCompletedUs_ = j;
    }

    public static void F(t tVar, List list) {
        com.google.protobuf.B b = tVar.perfSessions_;
        if (!((AbstractC4006b) b).a) {
            tVar.perfSessions_ = AbstractC4027v.r(b);
        }
        AbstractC4004a.a(list, tVar.perfSessions_);
    }

    public static void G(t tVar, r rVar) {
        tVar.getClass();
        tVar.httpMethod_ = rVar.a;
        tVar.bitField0_ |= 2;
    }

    public static void H(t tVar, long j) {
        tVar.bitField0_ |= 4;
        tVar.requestPayloadBytes_ = j;
    }

    public static void I(t tVar, long j) {
        tVar.bitField0_ |= 8;
        tVar.responsePayloadBytes_ = j;
    }

    public static t K() {
        return DEFAULT_INSTANCE;
    }

    public static p c0() {
        return (p) DEFAULT_INSTANCE.k();
    }

    public static void w(t tVar, String str) {
        tVar.getClass();
        str.getClass();
        tVar.bitField0_ |= 1;
        tVar.url_ = str;
    }

    public static void x(t tVar) {
        tVar.getClass();
        tVar.networkClientErrorReason_ = 1;
        tVar.bitField0_ |= 16;
    }

    public static void y(t tVar, int i) {
        tVar.bitField0_ |= 32;
        tVar.httpResponseCode_ = i;
    }

    public static void z(t tVar, String str) {
        tVar.getClass();
        str.getClass();
        tVar.bitField0_ |= 64;
        tVar.responseContentType_ = str;
    }

    public final long J() {
        return this.clientStartTimeUs_;
    }

    public final r L() {
        r rVarB = r.b(this.httpMethod_);
        return rVarB == null ? r.HTTP_METHOD_UNKNOWN : rVarB;
    }

    public final int M() {
        return this.httpResponseCode_;
    }

    public final com.google.protobuf.B N() {
        return this.perfSessions_;
    }

    public final long O() {
        return this.requestPayloadBytes_;
    }

    public final long P() {
        return this.responsePayloadBytes_;
    }

    public final long Q() {
        return this.timeToRequestCompletedUs_;
    }

    public final long R() {
        return this.timeToResponseCompletedUs_;
    }

    public final long S() {
        return this.timeToResponseInitiatedUs_;
    }

    public final String T() {
        return this.url_;
    }

    public final boolean U() {
        return (this.bitField0_ & 128) != 0;
    }

    public final boolean V() {
        return (this.bitField0_ & 2) != 0;
    }

    public final boolean W() {
        return (this.bitField0_ & 32) != 0;
    }

    public final boolean X() {
        return (this.bitField0_ & 4) != 0;
    }

    public final boolean Y() {
        return (this.bitField0_ & 8) != 0;
    }

    public final boolean Z() {
        return (this.bitField0_ & 256) != 0;
    }

    public final boolean a0() {
        return (this.bitField0_ & 1024) != 0;
    }

    public final boolean b0() {
        return (this.bitField0_ & com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH) != 0;
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
                return new C4007b0(DEFAULT_INSTANCE, "\u0001\r\u0000\u0001\u0001\r\r\u0001\u0001\u0000\u0001ဈ\u0000\u0002᠌\u0001\u0003ဂ\u0002\u0004ဂ\u0003\u0005င\u0005\u0006ဈ\u0006\u0007ဂ\u0007\bဂ\b\tဂ\t\nဂ\n\u000b᠌\u0004\f2\r\u001b", new Object[]{"bitField0_", "url_", "httpMethod_", C3978h.c, "requestPayloadBytes_", "responsePayloadBytes_", "httpResponseCode_", "responseContentType_", "clientStartTimeUs_", "timeToRequestCompletedUs_", "timeToResponseInitiatedUs_", "timeToResponseCompletedUs_", "networkClientErrorReason_", C3978h.d, "customAttributes_", q.a, "perfSessions_", z.class});
            case 3:
                return new t();
            case 4:
                return new p(DEFAULT_INSTANCE);
            case 5:
                return DEFAULT_INSTANCE;
            case 6:
                X x = PARSER;
                if (x != null) {
                    return x;
                }
                synchronized (t.class) {
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
