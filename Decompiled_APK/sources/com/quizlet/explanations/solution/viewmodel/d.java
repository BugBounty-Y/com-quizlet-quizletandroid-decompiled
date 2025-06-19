package com.quizlet.explanations.solution.viewmodel;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class d extends c {
    public final String a;

    public d(String imageUrl) {
        Intrinsics.checkNotNullParameter(imageUrl, "imageUrl");
        this.a = imageUrl;
    }

    @Override // com.quizlet.explanations.solution.viewmodel.c
    public final String a() {
        return this.a;
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
        return android.support.v4.media.session.a.t(new StringBuilder("RegularImageOverlayEvent(imageUrl="), this.a, ")");
    }
}
