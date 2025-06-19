package com.quizlet.inapp.model;

import com.google.android.play.core.review.ReviewInfo;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final ReviewInfo a;

    public a(ReviewInfo playReviewInfo) {
        Intrinsics.checkNotNullParameter(playReviewInfo, "playReviewInfo");
        this.a = playReviewInfo;
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
        return "InAppReviewInfo(playReviewInfo=" + this.a + ")";
    }
}
