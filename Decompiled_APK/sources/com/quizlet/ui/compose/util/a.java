package com.quizlet.ui.compose.util;

import androidx.compose.foundation.lazy.A;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final boolean a;
    public final A b;
    public final androidx.compose.foundation.lazy.grid.A c;

    public a(boolean z, A a, androidx.compose.foundation.lazy.grid.A a2, int i) {
        a = (i & 2) != 0 ? null : a;
        a2 = (i & 4) != 0 ? null : a2;
        this.a = z;
        this.b = a;
        this.c = a2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a == aVar.a && Intrinsics.b(this.b, aVar.b) && Intrinsics.b(this.c, aVar.c);
    }

    public final int hashCode() {
        int iHashCode = Boolean.hashCode(this.a) * 31;
        A a = this.b;
        int iHashCode2 = (iHashCode + (a == null ? 0 : a.hashCode())) * 31;
        androidx.compose.foundation.lazy.grid.A a2 = this.c;
        return iHashCode2 + (a2 != null ? a2.hashCode() : 0);
    }

    public final String toString() {
        return "ImpressionData(shouldCheckForImpression=" + this.a + ", lazyListState=" + this.b + ", lazyGridState=" + this.c + ")";
    }
}
