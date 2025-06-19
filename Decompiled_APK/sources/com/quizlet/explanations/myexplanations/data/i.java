package com.quizlet.explanations.myexplanations.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class i extends l {
    public final com.quizlet.qutils.string.f a;
    public final boolean b;

    public i(com.quizlet.qutils.string.f emptyHeader, boolean z) {
        Intrinsics.checkNotNullParameter(emptyHeader, "emptyHeader");
        this.a = emptyHeader;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof i)) {
            return false;
        }
        i iVar = (i) obj;
        return this.a.equals(iVar.a) && this.b == iVar.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Empty(emptyHeader=");
        sb.append(this.a);
        sb.append(", hasError=");
        return android.support.v4.media.session.a.o(")", sb, this.b);
    }
}
