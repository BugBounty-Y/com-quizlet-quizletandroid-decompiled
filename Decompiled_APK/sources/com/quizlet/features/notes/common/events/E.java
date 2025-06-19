package com.quizlet.features.notes.common.events;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class E implements y {
    public final List a;

    public E(List uris) {
        Intrinsics.checkNotNullParameter(uris, "uris");
        this.a = uris;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof E) && Intrinsics.b(this.a, ((E) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.n(")", new StringBuilder("ImagesSelected(uris="), this.a);
    }
}
