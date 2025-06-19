package com.google.firebase.perf.v1;

import com.google.protobuf.InterfaceC4029x;

/* loaded from: classes2.dex */
public enum i implements InterfaceC4029x {
    APPLICATION_PROCESS_STATE_UNKNOWN(0),
    FOREGROUND(1),
    BACKGROUND(2),
    FOREGROUND_BACKGROUND(3);

    public final int a;

    i(int i) {
        this.a = i;
    }

    @Override // com.google.protobuf.InterfaceC4029x
    public final int a() {
        return this.a;
    }
}
