package com.quizlet.features.practicetest.detail.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class o implements p {
    public final com.quizlet.ui.models.webpage.m a;

    public o(com.quizlet.ui.models.webpage.m webPage) {
        Intrinsics.checkNotNullParameter(webPage, "webPage");
        this.a = webPage;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof o) && Intrinsics.b(this.a, ((o) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "WebPageClicked(webPage=" + this.a + ")";
    }
}
