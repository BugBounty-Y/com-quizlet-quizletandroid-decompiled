package com.google.android.datatransport.runtime.firebase.transport;

/* loaded from: classes2.dex */
public enum c implements com.google.firebase.encoders.proto.b {
    REASON_UNKNOWN(0),
    MESSAGE_TOO_OLD(1),
    CACHE_FULL(2),
    PAYLOAD_TOO_BIG(3),
    MAX_RETRIES_REACHED(4),
    INVALID_PAYLOD(5),
    SERVER_ERROR(6);

    public final int a;

    c(int i2) {
        this.a = i2;
    }

    @Override // com.google.firebase.encoders.proto.b
    public final int a() {
        return this.a;
    }
}
