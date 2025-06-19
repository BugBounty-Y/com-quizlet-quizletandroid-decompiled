package com.quizlet.data.model;

import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class q2 implements t2 {
    public final ArrayList a;
    public final boolean b;

    public q2(ArrayList files, boolean z) {
        Intrinsics.checkNotNullParameter(files, "files");
        this.a = files;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof q2)) {
            return false;
        }
        q2 q2Var = (q2) obj;
        return this.a.equals(q2Var.a) && this.b == q2Var.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("File(files=");
        sb.append(this.a);
        sb.append(", isPrivate=");
        return android.support.v4.media.session.a.o(")", sb, this.b);
    }
}
