package com.quizlet.quizletandroid.ui.preview.viewmodel;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c extends d {
    public final List a;

    public c(List previews) {
        Intrinsics.checkNotNullParameter(previews, "previews");
        this.a = previews;
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
        return android.support.v4.media.session.a.n(")", new StringBuilder("Populated(previews="), this.a);
    }
}
