package com.google.firebase.perf.v1;

import com.google.protobuf.InterfaceC4029x;

/* loaded from: classes2.dex */
public enum r implements InterfaceC4029x {
    HTTP_METHOD_UNKNOWN(0),
    GET(1),
    PUT(2),
    POST(3),
    DELETE(4),
    HEAD(5),
    PATCH(6),
    OPTIONS(7),
    TRACE(8),
    CONNECT(9);

    public final int a;

    r(int i) {
        this.a = i;
    }

    public static r b(int i) {
        switch (i) {
            case 0:
                return HTTP_METHOD_UNKNOWN;
            case 1:
                return GET;
            case 2:
                return PUT;
            case 3:
                return POST;
            case 4:
                return DELETE;
            case 5:
                return HEAD;
            case 6:
                return PATCH;
            case 7:
                return OPTIONS;
            case 8:
                return TRACE;
            case 9:
                return CONNECT;
            default:
                return null;
        }
    }

    @Override // com.google.protobuf.InterfaceC4029x
    public final int a() {
        return this.a;
    }
}
