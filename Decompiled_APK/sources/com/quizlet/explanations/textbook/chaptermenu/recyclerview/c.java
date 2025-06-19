package com.quizlet.explanations.textbook.chaptermenu.recyclerview;

import androidx.compose.animation.d0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class c extends a {
    public final long a;
    public final String b;
    public final String c;
    public final boolean d;
    public final com.quizlet.explanations.solution.fragments.b e;

    public c(long j, String str, String name, boolean z, com.quizlet.explanations.solution.fragments.b onClickListener) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(onClickListener, "onClickListener");
        this.a = j;
        this.b = str;
        this.c = name;
        this.d = z;
        this.e = onClickListener;
    }

    public final boolean a() {
        return this.d;
    }

    public final Function1 b() {
        return this.e;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return this.a == cVar.a && Intrinsics.b(this.b, cVar.b) && Intrinsics.b(this.c, cVar.c) && this.d == cVar.d && this.e.equals(cVar.e);
    }

    @Override // com.quizlet.baserecyclerview.a
    public final Object getItemId() {
        return Long.valueOf(this.a);
    }

    public final int hashCode() {
        int iHashCode = Long.hashCode(this.a) * 31;
        String str = this.b;
        return this.e.hashCode() + d0.g(d0.e((iHashCode + (str == null ? 0 : str.hashCode())) * 31, 31, this.c), 31, this.d);
    }

    public final String toString() {
        return "ChapterMenuExercise(itemId=" + this.a + ", mediaExerciseId=" + this.b + ", name=" + this.c + ", hasSolutions=" + this.d + ", onClickListener=" + this.e + ")";
    }
}
