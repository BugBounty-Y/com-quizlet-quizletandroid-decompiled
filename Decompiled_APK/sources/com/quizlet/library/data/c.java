package com.quizlet.library.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements d {
    public final String a;

    public c(String section) {
        Intrinsics.checkNotNullParameter(section, "section");
        this.a = section;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof c) && Intrinsics.b(this.a, ((c) obj).a);
    }

    @Override // com.quizlet.library.data.d
    public final String getKey() {
        return this.a;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("Section(section="), this.a, ")");
    }
}
