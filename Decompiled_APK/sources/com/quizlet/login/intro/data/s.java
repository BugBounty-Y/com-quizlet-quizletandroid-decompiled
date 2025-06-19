package com.quizlet.login.intro.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class s implements t {
    public final com.quizlet.ui.models.webpage.b a;

    public s(com.quizlet.ui.models.webpage.b webPage) {
        Intrinsics.checkNotNullParameter(webPage, "webPage");
        this.a = webPage;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof s) && this.a.equals(((s) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "WebPage(webPage=" + this.a + ")";
    }
}
