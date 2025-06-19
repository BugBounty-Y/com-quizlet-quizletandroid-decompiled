package com.google.firebase.crashlytics.internal.model;

/* renamed from: com.google.firebase.crashlytics.internal.model.l0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3947l0 {
    public final C3949m0 a;
    public final C3953o0 b;
    public final C3951n0 c;

    public C3947l0(C3949m0 c3949m0, C3953o0 c3953o0, C3951n0 c3951n0) {
        this.a = c3949m0;
        this.b = c3953o0;
        this.c = c3951n0;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof C3947l0) {
            C3947l0 c3947l0 = (C3947l0) obj;
            if (this.a.equals(c3947l0.a) && this.b.equals(c3947l0.b) && this.c.equals(c3947l0.c)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return ((((this.a.hashCode() ^ 1000003) * 1000003) ^ this.b.hashCode()) * 1000003) ^ this.c.hashCode();
    }

    public final String toString() {
        return "StaticSessionData{appData=" + this.a + ", osData=" + this.b + ", deviceData=" + this.c + "}";
    }
}
