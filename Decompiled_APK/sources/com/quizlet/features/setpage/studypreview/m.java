package com.quizlet.features.setpage.studypreview;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3567z;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m extends AbstractC3567z {
    public final com.quizlet.features.setpage.studypreview.data.b a;

    public m(com.quizlet.features.setpage.studypreview.data.b data) {
        Intrinsics.checkNotNullParameter(data, "data");
        this.a = data;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof m) && Intrinsics.b(this.a, ((m) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "StudyPreviewDataLoaded(data=" + this.a + ")";
    }
}
