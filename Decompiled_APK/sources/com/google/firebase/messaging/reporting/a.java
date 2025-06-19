package com.google.firebase.messaging.reporting;

/* loaded from: classes2.dex */
public enum a implements com.google.firebase.encoders.proto.b {
    /* JADX INFO: Fake field, exist only in values array */
    UNKNOWN_EVENT(0),
    MESSAGE_DELIVERED(1),
    /* JADX INFO: Fake field, exist only in values array */
    MESSAGE_OPEN(2);

    public final int a;

    a(int i) {
        this.a = i;
    }

    @Override // com.google.firebase.encoders.proto.b
    public final int a() {
        return this.a;
    }
}
