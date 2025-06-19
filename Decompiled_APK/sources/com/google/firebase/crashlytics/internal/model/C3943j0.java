package com.google.firebase.crashlytics.internal.model;

/* renamed from: com.google.firebase.crashlytics.internal.model.j0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3943j0 extends L0 {
    public final int a;
    public final String b;
    public final String c;
    public final boolean d;

    public C3943j0(String str, int i, String str2, boolean z) {
        this.a = i;
        this.b = str;
        this.c = str2;
        this.d = z;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof L0) {
            L0 l0 = (L0) obj;
            if (this.a == ((C3943j0) l0).a) {
                C3943j0 c3943j0 = (C3943j0) l0;
                if (this.b.equals(c3943j0.b) && this.c.equals(c3943j0.c) && this.d == c3943j0.d) {
                    return true;
                }
            }
        }
        return false;
    }

    public final int hashCode() {
        return ((((((this.a ^ 1000003) * 1000003) ^ this.b.hashCode()) * 1000003) ^ this.c.hashCode()) * 1000003) ^ (this.d ? 1231 : 1237);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("OperatingSystem{platform=");
        sb.append(this.a);
        sb.append(", version=");
        sb.append(this.b);
        sb.append(", buildVersion=");
        sb.append(this.c);
        sb.append(", jailbroken=");
        return android.support.v4.media.session.a.o("}", sb, this.d);
    }
}
