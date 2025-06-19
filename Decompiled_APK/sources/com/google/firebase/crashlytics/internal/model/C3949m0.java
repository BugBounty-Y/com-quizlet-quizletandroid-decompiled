package com.google.firebase.crashlytics.internal.model;

/* renamed from: com.google.firebase.crashlytics.internal.model.m0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3949m0 {
    public final String a;
    public final String b;
    public final String c;
    public final String d;
    public final int e;
    public final com.google.firebase.crashlytics.internal.c f;

    public C3949m0(String str, String str2, String str3, String str4, int i, com.google.firebase.crashlytics.internal.c cVar) {
        if (str == null) {
            throw new NullPointerException("Null appIdentifier");
        }
        this.a = str;
        if (str2 == null) {
            throw new NullPointerException("Null versionCode");
        }
        this.b = str2;
        if (str3 == null) {
            throw new NullPointerException("Null versionName");
        }
        this.c = str3;
        if (str4 == null) {
            throw new NullPointerException("Null installUuid");
        }
        this.d = str4;
        this.e = i;
        this.f = cVar;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof C3949m0)) {
            return false;
        }
        C3949m0 c3949m0 = (C3949m0) obj;
        return this.a.equals(c3949m0.a) && this.b.equals(c3949m0.b) && this.c.equals(c3949m0.c) && this.d.equals(c3949m0.d) && this.e == c3949m0.e && this.f.equals(c3949m0.f);
    }

    public final int hashCode() {
        return ((((((((((this.a.hashCode() ^ 1000003) * 1000003) ^ this.b.hashCode()) * 1000003) ^ this.c.hashCode()) * 1000003) ^ this.d.hashCode()) * 1000003) ^ this.e) * 1000003) ^ this.f.hashCode();
    }

    public final String toString() {
        return "AppData{appIdentifier=" + this.a + ", versionCode=" + this.b + ", versionName=" + this.c + ", installUuid=" + this.d + ", deliveryMechanism=" + this.e + ", developmentPlatformProvider=" + this.f + "}";
    }
}
