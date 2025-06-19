package com.quizlet.features.achievements.achievement;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class h extends androidx.camera.core.impl.utils.e {
    public final String b;
    public final String c;
    public final String d;
    public final kotlinx.collections.immutable.b e;

    public h(String title, String description, String imageUrl, kotlinx.collections.immutable.b days) {
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(description, "description");
        Intrinsics.checkNotNullParameter(imageUrl, "imageUrl");
        Intrinsics.checkNotNullParameter(days, "days");
        this.b = title;
        this.c = description;
        this.d = imageUrl;
        this.e = days;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return Intrinsics.b(this.b, hVar.b) && Intrinsics.b(this.c, hVar.c) && Intrinsics.b(this.d, hVar.d) && Intrinsics.b(this.e, hVar.e);
    }

    public final int hashCode() {
        return this.e.hashCode() + d0.e(d0.e(this.b.hashCode() * 31, 31, this.c), 31, this.d);
    }

    public final String toString() {
        return "ExpiredStreak(title=" + this.b + ", description=" + this.c + ", imageUrl=" + this.d + ", days=" + this.e + ")";
    }
}
