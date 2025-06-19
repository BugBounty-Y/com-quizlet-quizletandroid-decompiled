package com.google.firebase.messaging.reporting;

/* loaded from: classes2.dex */
public enum b implements com.google.firebase.encoders.proto.b {
    /* JADX INFO: Fake field, exist only in values array */
    UNKNOWN(0),
    DATA_MESSAGE(1),
    /* JADX INFO: Fake field, exist only in values array */
    TOPIC(2),
    DISPLAY_NOTIFICATION(3);

    public final int a;

    b(int i) {
        this.a = i;
    }

    @Override // com.google.firebase.encoders.proto.b
    public final int a() {
        return this.a;
    }
}
