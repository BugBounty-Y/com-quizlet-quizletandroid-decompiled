package com.quizlet.quizletandroid.ui.subject.viewmodel;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g extends h {
    public final int a;
    public final kotlinx.collections.immutable.b b;
    public final int c;
    public final kotlinx.collections.immutable.b d;
    public final boolean e;
    public final boolean f;

    public g(int i, kotlinx.collections.immutable.b subjects, int i2, kotlinx.collections.immutable.b subjectSets, boolean z, boolean z2) {
        Intrinsics.checkNotNullParameter(subjects, "subjects");
        Intrinsics.checkNotNullParameter(subjectSets, "subjectSets");
        this.a = i;
        this.b = subjects;
        this.c = i2;
        this.d = subjectSets;
        this.e = z;
        this.f = z2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return this.a == gVar.a && Intrinsics.b(this.b, gVar.b) && this.c == gVar.c && Intrinsics.b(this.d, gVar.d) && this.e == gVar.e && this.f == gVar.f;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.f) + d0.g((this.d.hashCode() + d0.b(this.c, (this.b.hashCode() + (Integer.hashCode(this.a) * 31)) * 31, 31)) * 31, 31, this.e);
    }

    public final String toString() {
        return "Main(subjectCategoryTitleResId=" + this.a + ", subjects=" + this.b + ", selectedSubjectIndex=" + this.c + ", subjectSets=" + this.d + ", setsLoading=" + this.e + ", enableSearchCreateSet=" + this.f + ")";
    }
}
