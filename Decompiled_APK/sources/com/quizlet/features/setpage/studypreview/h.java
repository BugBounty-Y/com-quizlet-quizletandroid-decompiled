package com.quizlet.features.setpage.studypreview;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3567z;

/* loaded from: classes3.dex */
public final class h extends AbstractC3567z {
    public final boolean a;

    public h(boolean z) {
        this.a = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof h) && this.a == ((h) obj).a;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.o(")", new StringBuilder("FlashcardEngaged(isDragging="), this.a);
    }
}
