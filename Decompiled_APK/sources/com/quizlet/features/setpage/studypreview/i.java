package com.quizlet.features.setpage.studypreview;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3567z;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i extends AbstractC3567z {
    public final com.quizlet.features.setpage.studypreview.data.a a;

    public i(com.quizlet.features.setpage.studypreview.data.a data) {
        Intrinsics.checkNotNullParameter(data, "data");
        this.a = data;
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
        return "FlashcardFlipped(data=" + this.a + ")";
    }
}
