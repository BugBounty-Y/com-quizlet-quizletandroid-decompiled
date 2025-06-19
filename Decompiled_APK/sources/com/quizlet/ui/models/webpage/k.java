package com.quizlet.ui.models.webpage;

import com.quizlet.quizletandroid.R;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class k extends f {
    public final com.quizlet.data.model.search.c b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public k(com.quizlet.data.model.search.c model) {
        super(model.d);
        Intrinsics.checkNotNullParameter(model, "model");
        this.b = model;
    }

    @Override // com.quizlet.ui.models.webpage.m
    public final com.quizlet.qutils.string.g a() {
        com.quizlet.data.model.search.c cVar = this.b;
        Intrinsics.checkNotNullParameter(cVar, "<this>");
        int i = com.quizlet.ui.models.mappers.c.a[cVar.c.ordinal()];
        String string = cVar.b;
        if (i == 1) {
            Intrinsics.checkNotNullParameter(string, "string");
            return new com.quizlet.qutils.string.e(string);
        }
        if (i == 2) {
            Object[] args = {string};
            Intrinsics.checkNotNullParameter(args, "args");
            return new com.quizlet.qutils.string.f(R.string.revision_center_title, C4933y.P(args));
        }
        if (i != 3) {
            throw new NoWhenBranchMatchedException();
        }
        Intrinsics.checkNotNullParameter(string, "string");
        return new com.quizlet.qutils.string.e(string);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof k) && Intrinsics.b(this.b, ((k) obj).b);
    }

    public final int hashCode() {
        return this.b.hashCode();
    }

    public final String toString() {
        return "SearchBannerWebPage(model=" + this.b + ")";
    }
}
