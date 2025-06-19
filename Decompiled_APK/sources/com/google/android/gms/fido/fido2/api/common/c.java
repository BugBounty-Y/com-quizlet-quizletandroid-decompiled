package com.google.android.gms.fido.fido2.api.common;

/* loaded from: classes2.dex */
public enum c implements a {
    /* JADX INFO: Fake field, exist only in values array */
    RS256(-257),
    /* JADX INFO: Fake field, exist only in values array */
    RS384(-258),
    /* JADX INFO: Fake field, exist only in values array */
    RS512(-259),
    /* JADX INFO: Fake field, exist only in values array */
    LEGACY_RS1(-262),
    /* JADX INFO: Fake field, exist only in values array */
    PS256(-37),
    /* JADX INFO: Fake field, exist only in values array */
    PS384(-38),
    /* JADX INFO: Fake field, exist only in values array */
    PS512(-39),
    RS1(-65535);

    public final int a;

    c(int i) {
        this.a = i;
    }

    @Override // com.google.android.gms.fido.fido2.api.common.a
    public final int a() {
        return this.a;
    }
}
