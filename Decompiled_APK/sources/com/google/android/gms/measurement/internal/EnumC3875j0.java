package com.google.android.gms.measurement.internal;

/* renamed from: com.google.android.gms.measurement.internal.j0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public enum EnumC3875j0 {
    UNINITIALIZED("uninitialized"),
    POLICY("eu_consent_policy"),
    DENIED("denied"),
    GRANTED("granted");

    public final String a;

    EnumC3875j0(String str) {
        this.a = str;
    }

    @Override // java.lang.Enum
    public final String toString() {
        return this.a;
    }
}
