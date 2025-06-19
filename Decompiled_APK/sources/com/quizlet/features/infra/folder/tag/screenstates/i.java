package com.quizlet.features.infra.folder.tag.screenstates;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i implements j {
    public final List a;

    public i(List tagsNames) {
        Intrinsics.checkNotNullParameter(tagsNames, "tagsNames");
        this.a = tagsNames;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof i) && Intrinsics.b(this.a, ((i) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.n(")", new StringBuilder("UploadTags(tagsNames="), this.a);
    }
}
