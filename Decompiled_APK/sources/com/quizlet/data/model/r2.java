package com.quizlet.data.model;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class r2 implements t2 {
    public final Object a;
    public final boolean b;

    public r2(List setIds, boolean z) {
        Intrinsics.checkNotNullParameter(setIds, "setIds");
        this.a = setIds;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof r2)) {
            return false;
        }
        r2 r2Var = (r2) obj;
        return Intrinsics.b(this.a, r2Var.a) && this.b == r2Var.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FlashcardSet(setIds=");
        sb.append(this.a);
        sb.append(", isPrivate=");
        return android.support.v4.media.session.a.o(")", sb, this.b);
    }
}
