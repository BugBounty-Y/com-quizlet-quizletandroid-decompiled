package com.quizlet.learn.data;

import androidx.compose.animation.d0;
import java.util.ArrayList;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.learn.data.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4537b {
    public final List a;
    public final List b;
    public final List c;
    public final List d;
    public final List e;

    public C4537b(List terms, List diagramShapes, List diagramImageRefs, List answers, List questionAttributes) {
        Intrinsics.checkNotNullParameter(terms, "terms");
        Intrinsics.checkNotNullParameter(diagramShapes, "diagramShapes");
        Intrinsics.checkNotNullParameter(diagramImageRefs, "diagramImageRefs");
        Intrinsics.checkNotNullParameter(answers, "answers");
        Intrinsics.checkNotNullParameter(questionAttributes, "questionAttributes");
        this.a = terms;
        this.b = diagramShapes;
        this.c = diagramImageRefs;
        this.d = answers;
        this.e = questionAttributes;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r7v3, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r8v2, types: [java.util.List] */
    public static C4537b a(C4537b c4537b, ArrayList arrayList, kotlin.collections.K k, int i) {
        ArrayList arrayList2 = arrayList;
        if ((i & 1) != 0) {
            arrayList2 = c4537b.a;
        }
        ArrayList terms = arrayList2;
        List diagramShapes = c4537b.b;
        List diagramImageRefs = c4537b.c;
        kotlin.collections.K k2 = k;
        if ((i & 8) != 0) {
            k2 = c4537b.d;
        }
        kotlin.collections.K answers = k2;
        List questionAttributes = c4537b.e;
        c4537b.getClass();
        Intrinsics.checkNotNullParameter(terms, "terms");
        Intrinsics.checkNotNullParameter(diagramShapes, "diagramShapes");
        Intrinsics.checkNotNullParameter(diagramImageRefs, "diagramImageRefs");
        Intrinsics.checkNotNullParameter(answers, "answers");
        Intrinsics.checkNotNullParameter(questionAttributes, "questionAttributes");
        return new C4537b(terms, diagramShapes, diagramImageRefs, answers, questionAttributes);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4537b)) {
            return false;
        }
        C4537b c4537b = (C4537b) obj;
        return Intrinsics.b(this.a, c4537b.a) && Intrinsics.b(this.b, c4537b.b) && Intrinsics.b(this.c, c4537b.c) && Intrinsics.b(this.d, c4537b.d) && Intrinsics.b(this.e, c4537b.e);
    }

    public final int hashCode() {
        return this.e.hashCode() + d0.f(d0.f(d0.f(this.a.hashCode() * 31, 31, this.b), 31, this.c), 31, this.d);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("LearnDataTuple(terms=");
        sb.append(this.a);
        sb.append(", diagramShapes=");
        sb.append(this.b);
        sb.append(", diagramImageRefs=");
        sb.append(this.c);
        sb.append(", answers=");
        sb.append(this.d);
        sb.append(", questionAttributes=");
        return android.support.v4.media.session.a.n(")", sb, this.e);
    }
}
