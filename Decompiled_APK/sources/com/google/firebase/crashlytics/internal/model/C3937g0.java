package com.google.firebase.crashlytics.internal.model;

/* renamed from: com.google.firebase.crashlytics.internal.model.g0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3937g0 extends H0 {
    public final String a;
    public final String b;

    public C3937g0(String str, String str2) {
        this.a = str;
        this.b = str2;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof H0) {
            H0 h0 = (H0) obj;
            if (this.a.equals(((C3937g0) h0).a) && this.b.equals(((C3937g0) h0).b)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return ((this.a.hashCode() ^ 1000003) * 1000003) ^ this.b.hashCode();
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RolloutVariant{rolloutId=");
        sb.append(this.a);
        sb.append(", variantId=");
        return android.support.v4.media.session.a.t(sb, this.b, "}");
    }
}
