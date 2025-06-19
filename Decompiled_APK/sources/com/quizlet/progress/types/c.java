package com.quizlet.progress.types;

import androidx.compose.animation.d0;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c {
    public final long a;
    public final ArrayList b;
    public final Long c;

    public c(long j, ArrayList itemIds, Long l) {
        Intrinsics.checkNotNullParameter(itemIds, "itemIds");
        this.a = j;
        this.b = itemIds;
        this.c = l;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return this.a == cVar.a && this.b.equals(cVar.b) && Intrinsics.b(this.c, cVar.c);
    }

    public final int hashCode() {
        int iH = d0.h(this.b, Long.hashCode(this.a) * 31, 31);
        Long l = this.c;
        return iH + (l == null ? 0 : l.hashCode());
    }

    public final String toString() {
        return "ContainerInfo(containerId=" + this.a + ", itemIds=" + this.b + ", resetTime=" + this.c + ")";
    }
}
