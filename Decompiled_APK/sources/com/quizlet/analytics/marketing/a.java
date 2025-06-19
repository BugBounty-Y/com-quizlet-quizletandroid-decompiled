package com.quizlet.analytics.marketing;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a {
    public final String a;

    public a(String route) {
        Intrinsics.checkNotNullParameter(route, "route");
        this.a = route;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof a) && Intrinsics.b(this.a, ((a) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("DeepLinkData(route="), this.a, ")");
    }
}
