package com.quizlet.diagrams;

import androidx.recyclerview.widget.F0;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a {
    public final Pair a;
    public final F0 b;
    public final boolean c;

    public a(Pair item, F0 holder, boolean z) {
        Intrinsics.checkNotNullParameter(item, "item");
        Intrinsics.checkNotNullParameter(holder, "holder");
        this.a = item;
        this.b = holder;
        this.c = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && Intrinsics.b(this.b, aVar.b) && this.c == aVar.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("CardClickEvent(item=");
        sb.append(this.a);
        sb.append(", holder=");
        sb.append(this.b);
        sb.append(", isCurrent=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }
}
