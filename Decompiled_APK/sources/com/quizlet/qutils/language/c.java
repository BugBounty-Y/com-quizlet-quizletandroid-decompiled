package com.quizlet.qutils.language;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements e {
    public final String a;

    public c(String languageName) {
        Intrinsics.checkNotNullParameter(languageName, "languageName");
        this.a = languageName;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof c) && Intrinsics.b(this.a, ((c) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("Language(languageName="), this.a, ")");
    }
}
