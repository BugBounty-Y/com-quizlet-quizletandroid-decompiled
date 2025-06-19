package com.quizlet.features.achievements.achievement;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class i extends androidx.camera.core.impl.utils.e {
    public final int b;
    public final String c;
    public final String d;
    public final String e;
    public final kotlinx.collections.immutable.b f;

    public i(int i, String title, String description, String imageUrl, kotlinx.collections.immutable.b days) {
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(description, "description");
        Intrinsics.checkNotNullParameter(imageUrl, "imageUrl");
        Intrinsics.checkNotNullParameter(days, "days");
        this.b = i;
        this.c = title;
        this.d = description;
        this.e = imageUrl;
        this.f = days;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof i)) {
            return false;
        }
        i iVar = (i) obj;
        return this.b == iVar.b && Intrinsics.b(this.c, iVar.c) && Intrinsics.b(this.d, iVar.d) && Intrinsics.b(this.e, iVar.e) && Intrinsics.b(this.f, iVar.f);
    }

    public final int hashCode() {
        return this.f.hashCode() + d0.e(d0.e(d0.e(Integer.hashCode(this.b) * 31, 31, this.c), 31, this.d), 31, this.e);
    }

    public final String toString() {
        return "HasStreak(streakValue=" + this.b + ", title=" + this.c + ", description=" + this.d + ", imageUrl=" + this.e + ", days=" + this.f + ")";
    }
}
