package com.quizlet.features.achievements.achievement;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class j extends androidx.camera.core.impl.utils.e {
    public final String b;
    public final String c;
    public final String d;

    public j(String title, String description, String imageUrl) {
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(description, "description");
        Intrinsics.checkNotNullParameter(imageUrl, "imageUrl");
        this.b = title;
        this.c = description;
        this.d = imageUrl;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof j)) {
            return false;
        }
        j jVar = (j) obj;
        return Intrinsics.b(this.b, jVar.b) && Intrinsics.b(this.c, jVar.c) && Intrinsics.b(this.d, jVar.d);
    }

    public final int hashCode() {
        return this.d.hashCode() + d0.e(this.b.hashCode() * 31, 31, this.c);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("NoStreak(title=");
        sb.append(this.b);
        sb.append(", description=");
        sb.append(this.c);
        sb.append(", imageUrl=");
        return android.support.v4.media.session.a.t(sb, this.d, ")");
    }
}
