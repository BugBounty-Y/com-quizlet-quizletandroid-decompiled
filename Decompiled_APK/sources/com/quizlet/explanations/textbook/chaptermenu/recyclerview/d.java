package com.quizlet.explanations.textbook.chaptermenu.recyclerview;

import androidx.compose.animation.d0;
import com.quizlet.data.model.ExerciseGroup;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class d extends a {
    public final long a;
    public final String b;
    public final String c;
    public final ExerciseGroup d;
    public final boolean e;
    public final com.quizlet.explanations.solution.fragments.b f;

    public d(long j, String str, String title, ExerciseGroup exerciseGroupData, boolean z, com.quizlet.explanations.solution.fragments.b onClickListener) {
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(exerciseGroupData, "exerciseGroupData");
        Intrinsics.checkNotNullParameter(onClickListener, "onClickListener");
        this.a = j;
        this.b = str;
        this.c = title;
        this.d = exerciseGroupData;
        this.e = z;
        this.f = onClickListener;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return this.a == dVar.a && Intrinsics.b(this.b, dVar.b) && Intrinsics.b(this.c, dVar.c) && this.d.equals(dVar.d) && this.e == dVar.e && this.f.equals(dVar.f);
    }

    @Override // com.quizlet.baserecyclerview.a
    public final Object getItemId() {
        return Long.valueOf(this.a);
    }

    public final int hashCode() {
        int iHashCode = Long.hashCode(this.a) * 31;
        String str = this.b;
        return this.f.hashCode() + d0.g((this.d.hashCode() + d0.e((iHashCode + (str == null ? 0 : str.hashCode())) * 31, 31, this.c)) * 31, 31, this.e);
    }

    public final String toString() {
        return "ChapterMenuExerciseGroup(itemId=" + this.a + ", page=" + this.b + ", title=" + this.c + ", exerciseGroupData=" + this.d + ", hasSolutions=" + this.e + ", onClickListener=" + this.f + ")";
    }
}
