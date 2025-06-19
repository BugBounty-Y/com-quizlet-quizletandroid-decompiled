package com.quizlet.data.model;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class Exercise {
    public final long a;
    public final String b;
    public final String c;
    public final boolean d;
    public final String e;

    public Exercise(long j, String str, String name, boolean z, String webUrl) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(webUrl, "webUrl");
        this.a = j;
        this.b = str;
        this.c = name;
        this.d = z;
        this.e = webUrl;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Exercise)) {
            return false;
        }
        Exercise exercise = (Exercise) obj;
        return this.a == exercise.a && Intrinsics.b(this.b, exercise.b) && Intrinsics.b(this.c, exercise.c) && this.d == exercise.d && Intrinsics.b(this.e, exercise.e);
    }

    public final int hashCode() {
        int iHashCode = Long.hashCode(this.a) * 31;
        String str = this.b;
        return this.e.hashCode() + androidx.compose.animation.d0.g(androidx.compose.animation.d0.e((iHashCode + (str == null ? 0 : str.hashCode())) * 31, 31, this.c), 31, this.d);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Exercise(id=");
        sb.append(this.a);
        sb.append(", mediaExerciseId=");
        sb.append(this.b);
        sb.append(", name=");
        sb.append(this.c);
        sb.append(", hasSolution=");
        sb.append(this.d);
        sb.append(", webUrl=");
        return android.support.v4.media.session.a.t(sb, this.e, ")");
    }
}
