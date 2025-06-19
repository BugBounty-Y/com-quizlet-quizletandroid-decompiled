package com.quizlet.features.setpage.studypreview;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3567z;

/* loaded from: classes3.dex */
public final class j extends AbstractC3567z {
    public final int a;

    public j(int i) {
        this.a = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof j) && this.a == ((j) obj).a;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.r(new StringBuilder("FlashcardScrolled(visibleTermIndex="), this.a, ")");
    }
}
