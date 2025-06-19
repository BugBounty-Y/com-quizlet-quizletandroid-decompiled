package com.quizlet.explanations.myexplanations.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class h implements com.quizlet.baserecyclerview.a {
    public final String a;
    public final int b;

    public h(String itemId, int i) {
        Intrinsics.checkNotNullParameter(itemId, "itemId");
        this.a = itemId;
        this.b = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return this.a.equals(hVar.a) && this.b == hVar.b;
    }

    @Override // com.quizlet.baserecyclerview.a
    public final Object getItemId() {
        return this.a;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("MyExplanationsHeaderItem(itemId=");
        sb.append(this.a);
        sb.append(", titleStringRes=");
        return android.support.v4.media.session.a.r(sb, this.b, ")");
    }
}
