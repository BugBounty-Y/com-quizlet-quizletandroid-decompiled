package com.quizlet.quizletandroid.ui.preview.dataclass;

import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.animation.d0;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final long a;
    public final String b;
    public final int c;
    public final ArrayList d;

    public a(long j, String title, int i, ArrayList termList) {
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(termList, "termList");
        this.a = j;
        this.b = title;
        this.c = i;
        this.d = termList;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a == aVar.a && Intrinsics.b(this.b, aVar.b) && this.c == aVar.c && this.d.equals(aVar.d);
    }

    public final int hashCode() {
        return this.d.hashCode() + d0.b(this.c, d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PreviewData(id=");
        sb.append(this.a);
        sb.append(", title=");
        sb.append(this.b);
        sb.append(", numberOfTerms=");
        sb.append(this.c);
        sb.append(", termList=");
        return AbstractC0147y.f(")", sb, this.d);
    }
}
