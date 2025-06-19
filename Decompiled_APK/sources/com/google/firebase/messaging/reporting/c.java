package com.google.firebase.messaging.reporting;

/* loaded from: classes2.dex */
public enum c implements com.google.firebase.encoders.proto.b {
    /* JADX INFO: Fake field, exist only in values array */
    UNKNOWN_OS(0),
    ANDROID(1),
    /* JADX INFO: Fake field, exist only in values array */
    IOS(2),
    /* JADX INFO: Fake field, exist only in values array */
    WEB(3);

    public final int a;

    c(int i) {
        this.a = i;
    }

    @Override // com.google.firebase.encoders.proto.b
    public final int a() {
        return this.a;
    }
}
