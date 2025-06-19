package com.google.firebase.perf.v1;

import com.google.protobuf.InterfaceC4029x;

/* loaded from: classes2.dex */
public enum A implements InterfaceC4029x {
    SESSION_VERBOSITY_NONE(0),
    GAUGES_AND_SYSTEM_EVENTS(1);

    public final int a;

    A(int i) {
        this.a = i;
    }

    @Override // com.google.protobuf.InterfaceC4029x
    public final int a() {
        return this.a;
    }
}
