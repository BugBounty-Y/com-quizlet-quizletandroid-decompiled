package com.google.firebase.sessions;

/* renamed from: com.google.firebase.sessions.j, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public enum EnumC3988j implements com.google.firebase.encoders.json.f {
    /* JADX INFO: Fake field, exist only in values array */
    COLLECTION_UNKNOWN(0),
    COLLECTION_SDK_NOT_INSTALLED(1),
    COLLECTION_ENABLED(2),
    COLLECTION_DISABLED(3),
    /* JADX INFO: Fake field, exist only in values array */
    COLLECTION_DISABLED_REMOTE(4),
    /* JADX INFO: Fake field, exist only in values array */
    COLLECTION_SAMPLED(5);

    public final int a;

    EnumC3988j(int i) {
        this.a = i;
    }

    @Override // com.google.firebase.encoders.json.f
    public final int a() {
        return this.a;
    }
}
