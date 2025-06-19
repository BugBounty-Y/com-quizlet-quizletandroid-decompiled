package com.quizlet.richtext.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final String a;

    public a(String jsonValue) {
        Intrinsics.checkNotNullParameter(jsonValue, "jsonValue");
        this.a = jsonValue;
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
        return android.support.v4.media.session.a.t(new StringBuilder("RichTextPayload(jsonValue="), this.a, ")");
    }
}
