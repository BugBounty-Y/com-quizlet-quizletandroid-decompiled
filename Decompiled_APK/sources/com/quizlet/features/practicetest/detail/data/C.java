package com.quizlet.features.practicetest.detail.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class C implements D {
    public final com.quizlet.ui.models.webpage.m a;

    public C(com.quizlet.ui.models.webpage.m webPage) {
        Intrinsics.checkNotNullParameter(webPage, "webPage");
        this.a = webPage;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C) && Intrinsics.b(this.a, ((C) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "WebPage(webPage=" + this.a + ")";
    }
}
