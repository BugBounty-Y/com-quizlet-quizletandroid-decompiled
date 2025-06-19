package com.quizlet.features.universaluploadflow.pastetext.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d implements g {
    public final String a;

    public d(String text) {
        Intrinsics.checkNotNullParameter(text, "text");
        this.a = text;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof d) && Intrinsics.b(this.a, ((d) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("GenerateButtonClicked(text="), this.a, ")");
    }
}
