package com.quizlet.assembly.compose.links;

import androidx.compose.ui.graphics.C0861v;
import kotlin.C;
import kotlin.D;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b implements c {
    public final Function2 a;
    public final String b;
    public final C0861v c;

    public b(Function2 painter, String str, C0861v c0861v) {
        Intrinsics.checkNotNullParameter(painter, "painter");
        this.a = painter;
        this.b = str;
        this.c = c0861v;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return Intrinsics.b(this.a, bVar.a) && Intrinsics.b(this.b, bVar.b) && Intrinsics.b(this.c, bVar.c);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        int iHashCode2 = 0;
        String str = this.b;
        int iHashCode3 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        C0861v c0861v = this.c;
        if (c0861v != null) {
            long j = c0861v.a;
            C c = D.b;
            iHashCode2 = Long.hashCode(j);
        }
        return iHashCode3 + iHashCode2;
    }

    public final String toString() {
        return "Trailing(painter=" + this.a + ", contentDescription=" + this.b + ", tint=" + this.c + ")";
    }
}
