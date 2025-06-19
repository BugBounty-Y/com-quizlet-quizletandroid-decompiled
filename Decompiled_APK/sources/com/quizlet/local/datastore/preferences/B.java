package com.quizlet.local.datastore.preferences;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class B {
    public final String a;
    public final String b;

    public B(String cookie, String uri) {
        Intrinsics.checkNotNullParameter(cookie, "cookie");
        Intrinsics.checkNotNullParameter(uri, "uri");
        this.a = cookie;
        this.b = uri;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof B)) {
            return false;
        }
        B b = (B) obj;
        return Intrinsics.b(this.a, b.a) && Intrinsics.b(this.b, b.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("CookieData(cookie=");
        sb.append(this.a);
        sb.append(", uri=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
