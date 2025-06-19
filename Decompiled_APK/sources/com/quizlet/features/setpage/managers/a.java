package com.quizlet.features.setpage.managers;

import com.quizlet.quizletandroid.ui.startpage.nav2.viewholder.w;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final int a;
    public final w b;

    public a(int i, w undoAction) {
        Intrinsics.checkNotNullParameter(undoAction, "undoAction");
        this.a = i;
        this.b = undoAction;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a == aVar.a && this.b.equals(aVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "OnComplete(setsIdsSize=" + this.a + ", undoAction=" + this.b + ")";
    }
}
