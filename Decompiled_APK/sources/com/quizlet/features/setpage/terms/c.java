package com.quizlet.features.setpage.terms;

import com.quizlet.quizletandroid.R;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements d {
    public final int a;
    public final boolean b;
    public final com.quizlet.qutils.string.d c;
    public final com.quizlet.qutils.string.d d;

    public c(int i, boolean z) {
        this.a = i;
        this.b = z;
        Object[] args = {Integer.valueOf(i)};
        Intrinsics.checkNotNullParameter(args, "args");
        this.c = new com.quizlet.qutils.string.d(R.plurals.set_page_study_selected_terms_quantity, i, C4933y.P(args));
        Object[] args2 = {Integer.valueOf(i)};
        Intrinsics.checkNotNullParameter(args2, "args");
        this.d = new com.quizlet.qutils.string.d(R.plurals.set_page_study_selected_terms_quantity_description, i, C4933y.P(args2));
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return this.a == cVar.a && this.b == cVar.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "Visible(numSelectedTerms=" + this.a + ", isSelected=" + this.b + ")";
    }
}
