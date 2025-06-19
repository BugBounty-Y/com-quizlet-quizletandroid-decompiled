package com.quizlet.upgrade.data;

import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class s extends v {
    public final com.quizlet.search.composables.E b;
    public final kotlin.u c;
    public final int d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public s(com.quizlet.search.composables.E onLinkClicked) {
        super(false);
        Intrinsics.checkNotNullParameter(onLinkClicked, "onLinkClicked");
        this.b = onLinkClicked;
        this.c = kotlin.l.b(new r(this, 0));
        this.d = R.string.disclaimer_teacher_features;
    }

    @Override // com.quizlet.upgrade.data.v
    public final com.quizlet.qutils.string.g a() {
        return (com.quizlet.qutils.string.g) this.c.getValue();
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof s) && this.b.equals(((s) obj).b);
    }

    @Override // com.quizlet.baserecyclerview.a
    public final Object getItemId() {
        return Integer.valueOf(this.d);
    }

    public final int hashCode() {
        return this.b.hashCode();
    }

    public final String toString() {
        return "TeacherFeaturesDisclaimer(onLinkClicked=" + this.b + ")";
    }
}
