package com.quizlet.login.parentemail.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m implements n {
    public final com.quizlet.ui.models.webpage.b a;

    public m(com.quizlet.ui.models.webpage.b webPage) {
        Intrinsics.checkNotNullParameter(webPage, "webPage");
        this.a = webPage;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof m) && this.a.equals(((m) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "WebPage(webPage=" + this.a + ")";
    }
}
