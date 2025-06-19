package com.quizlet.explanations.textbook.exercisedetail.recyclerview.footer;

import androidx.compose.animation.d0;
import com.quizlet.quizletandroid.R;
import kotlin.collections.C4933y;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b {
    public final String a;
    public final String b;
    public final C4956o c;
    public final com.quizlet.qutils.string.f d;

    /* JADX WARN: Multi-variable type inference failed */
    public b(String str, String name, Function1 onClick) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        this.a = str;
        this.b = name;
        this.c = (C4956o) onClick;
        Object[] args = {name};
        Intrinsics.checkNotNullParameter(args, "args");
        this.d = new com.quizlet.qutils.string.f(R.string.exercise_name, C4933y.P(args));
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return Intrinsics.b(this.a, bVar.a) && Intrinsics.b(this.b, bVar.b) && this.c.equals(bVar.c);
    }

    public final int hashCode() {
        String str = this.a;
        return this.c.hashCode() + d0.e((str == null ? 0 : str.hashCode()) * 31, 31, this.b);
    }

    public final String toString() {
        return "ExerciseDetailFooter(id=" + this.a + ", name=" + this.b + ", onClick=" + this.c + ")";
    }
}
