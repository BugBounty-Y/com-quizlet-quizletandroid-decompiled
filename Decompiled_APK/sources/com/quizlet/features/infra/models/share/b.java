package com.quizlet.features.infra.models.share;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final String a;
    public final com.quizlet.utmhelper.a b;

    public b(String webUrl, com.quizlet.utmhelper.a utmParams) {
        Intrinsics.checkNotNullParameter(webUrl, "webUrl");
        Intrinsics.checkNotNullParameter(utmParams, "utmParams");
        this.a = webUrl;
        this.b = utmParams;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return Intrinsics.b(this.a, bVar.a) && Intrinsics.b(this.b, bVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "ShareResultData(webUrl=" + this.a + ", utmParams=" + this.b + ")";
    }
}
