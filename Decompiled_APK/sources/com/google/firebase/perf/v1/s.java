package com.google.firebase.perf.v1;

import com.google.protobuf.InterfaceC4029x;

/* loaded from: classes2.dex */
public enum s implements InterfaceC4029x {
    NETWORK_CLIENT_ERROR_REASON_UNKNOWN(0),
    GENERIC_CLIENT_ERROR(1);

    public final int a;

    s(int i) {
        this.a = i;
    }

    @Override // com.google.protobuf.InterfaceC4029x
    public final int a() {
        return this.a;
    }
}
