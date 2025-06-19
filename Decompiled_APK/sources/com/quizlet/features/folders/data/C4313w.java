package com.quizlet.features.folders.data;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.folders.data.w, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4313w implements T {
    public final com.quizlet.ui.models.content.listitem.o a;
    public final int b;
    public final boolean c;

    public C4313w(com.quizlet.ui.models.content.listitem.o item, int i, boolean z) {
        Intrinsics.checkNotNullParameter(item, "item");
        this.a = item;
        this.b = i;
        this.c = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4313w)) {
            return false;
        }
        C4313w c4313w = (C4313w) obj;
        return Intrinsics.b(this.a, c4313w.a) && this.b == c4313w.b && this.c == c4313w.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + androidx.compose.animation.d0.b(this.b, this.a.hashCode() * 31, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("MaterialImpressed(item=");
        sb.append(this.a);
        sb.append(", position=");
        sb.append(this.b);
        sb.append(", isRecommendation=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }
}
