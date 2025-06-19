package com.quizlet.features.setpage.terms;

import java.util.List;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f implements g {
    public final List a;
    public final List b;

    public f(List data, List diagramData) {
        Intrinsics.checkNotNullParameter(data, "data");
        Intrinsics.checkNotNullParameter(diagramData, "diagramData");
        this.a = data;
        this.b = diagramData;
    }

    public static f a(f fVar, List data, List diagramData, int i) {
        if ((i & 1) != 0) {
            data = fVar.a;
        }
        if ((i & 2) != 0) {
            diagramData = fVar.b;
        }
        fVar.getClass();
        Intrinsics.checkNotNullParameter(data, "data");
        Intrinsics.checkNotNullParameter(diagramData, "diagramData");
        return new f(data, diagramData);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof f)) {
            return false;
        }
        f fVar = (f) obj;
        return Intrinsics.b(this.a, fVar.a) && Intrinsics.b(this.b, fVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "TermList(data=" + this.a + ", diagramData=" + this.b + ")";
    }

    public f(List list, int i) {
        this((i & 1) != 0 ? K.a : list, K.a);
    }
}
