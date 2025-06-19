package com.google.firebase.sessions;

/* loaded from: classes2.dex */
public enum C implements com.google.firebase.encoders.json.f {
    /* JADX INFO: Fake field, exist only in values array */
    LOG_ENVIRONMENT_UNKNOWN(0),
    /* JADX INFO: Fake field, exist only in values array */
    LOG_ENVIRONMENT_AUTOPUSH(1),
    /* JADX INFO: Fake field, exist only in values array */
    LOG_ENVIRONMENT_STAGING(2),
    LOG_ENVIRONMENT_PROD(3);

    public final int a;

    C(int i) {
        this.a = i;
    }

    @Override // com.google.firebase.encoders.json.f
    public final int a() {
        return this.a;
    }
}
