package com.quizlet.features.universaluploadflow.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class q implements r {
    public final com.quizlet.ui.models.webpage.m a;

    public q(com.quizlet.ui.models.webpage.m webPage) {
        Intrinsics.checkNotNullParameter(webPage, "webPage");
        this.a = webPage;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof q) && Intrinsics.b(this.a, ((q) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "WebPageClicked(webPage=" + this.a + ")";
    }
}
