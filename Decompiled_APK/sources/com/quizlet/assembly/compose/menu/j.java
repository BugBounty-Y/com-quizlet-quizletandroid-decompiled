package com.quizlet.assembly.compose.menu;

import androidx.compose.ui.graphics.C0861v;
import kotlin.C;
import kotlin.D;

/* loaded from: classes2.dex */
public final class j {
    public final long a;
    public final long b;

    public j(long j, long j2) {
        this.a = j;
        this.b = j2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || !(obj instanceof j)) {
            return false;
        }
        j jVar = (j) obj;
        return C0861v.c(this.a, jVar.a) && C0861v.c(this.b, jVar.b);
    }

    public final int hashCode() {
        int i = C0861v.h;
        C c = D.b;
        return Long.hashCode(this.b) + (Long.hashCode(this.a) * 31);
    }
}
