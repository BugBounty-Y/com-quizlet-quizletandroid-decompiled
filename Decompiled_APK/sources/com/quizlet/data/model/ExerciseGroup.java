package com.quizlet.data.model;

import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@com.squareup.moshi.m(generateAdapter = true)
@Metadata
/* loaded from: classes2.dex */
public final class ExerciseGroup extends TableOfContentItem implements InterfaceC4141k0 {
    public final long a;
    public final boolean b;
    public final String c;
    public final String d;
    public final List e;

    public ExerciseGroup(long j, String title, String str, boolean z, List exercises) {
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(exercises, "exercises");
        this.a = j;
        this.b = z;
        this.c = title;
        this.d = str;
        this.e = exercises;
    }

    @Override // com.quizlet.data.model.InterfaceC4141k0
    public final List a() {
        return this.e;
    }

    @Override // com.quizlet.data.model.TableOfContentItem
    public final long b() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ExerciseGroup)) {
            return false;
        }
        ExerciseGroup exerciseGroup = (ExerciseGroup) obj;
        return this.a == exerciseGroup.a && this.b == exerciseGroup.b && Intrinsics.b(this.c, exerciseGroup.c) && Intrinsics.b(this.d, exerciseGroup.d) && Intrinsics.b(this.e, exerciseGroup.e);
    }

    public final int hashCode() {
        int iE = androidx.compose.animation.d0.e(androidx.compose.animation.d0.g(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c);
        String str = this.d;
        return this.e.hashCode() + ((iE + (str == null ? 0 : str.hashCode())) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ExerciseGroup(id=");
        sb.append(this.a);
        sb.append(", hasSolutions=");
        sb.append(this.b);
        sb.append(", title=");
        sb.append(this.c);
        sb.append(", page=");
        sb.append(this.d);
        sb.append(", exercises=");
        return android.support.v4.media.session.a.n(")", sb, this.e);
    }
}
