package com.quizlet.upgrade.paywall.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends c {
    public final String a;
    public final com.quizlet.features.infra.models.upgrade.a b;

    public b(String source, com.quizlet.features.infra.models.upgrade.a navigationSource) {
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(navigationSource, "navigationSource");
        this.a = source;
        this.b = navigationSource;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return Intrinsics.b(this.a, bVar.a) && this.b == bVar.b;
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "ShowQuizletPlusScreen(source=" + this.a + ", navigationSource=" + this.b + ")";
    }
}
