package com.quizlet.features.setpage.termlist.data;

import androidx.appcompat.app.y;
import com.quizlet.quizletandroid.R;
import kotlin.collections.B;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends y {
    public final int d;
    public final boolean e;

    public b(int i, boolean z) {
        super(Boolean.valueOf(z), B.j(Boolean.FALSE, Boolean.TRUE));
        this.d = i;
        this.e = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return this.d == bVar.d && this.e == bVar.e;
    }

    @Override // androidx.appcompat.app.y
    public final com.quizlet.qutils.string.g g(int i) {
        if (i == 0) {
            Object[] args = new Object[0];
            Intrinsics.checkNotNullParameter(args, "args");
            return new com.quizlet.qutils.string.f(R.string.set_page_study_all_description, C4933y.P(args));
        }
        int i2 = this.d;
        Object[] args2 = {Integer.valueOf(i2)};
        Intrinsics.checkNotNullParameter(args2, "args");
        return new com.quizlet.qutils.string.d(R.plurals.set_page_study_selected_terms_quantity_description, i2, C4933y.P(args2));
    }

    public final int hashCode() {
        return Boolean.hashCode(this.e) + (Integer.hashCode(this.d) * 31);
    }

    @Override // androidx.appcompat.app.y
    public final com.quizlet.qutils.string.g m(int i) {
        if (i == 0) {
            Object[] args = new Object[0];
            Intrinsics.checkNotNullParameter(args, "args");
            return new com.quizlet.qutils.string.f(R.string.set_page_study_all, C4933y.P(args));
        }
        int i2 = this.d;
        Object[] args2 = {Integer.valueOf(i2)};
        Intrinsics.checkNotNullParameter(args2, "args");
        return new com.quizlet.qutils.string.d(R.plurals.set_page_study_selected_terms_quantity, i2, C4933y.P(args2));
    }

    @Override // androidx.appcompat.app.y
    public final String toString() {
        return "SelectedTermControlState(numSelectedTerms=" + this.d + ", isSelected=" + this.e + ")";
    }
}
