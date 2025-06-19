package com.quizlet.explanations.questiondetail.data;

import androidx.compose.animation.d0;
import androidx.compose.foundation.text.z0;
import androidx.compose.ui.platform.C0960p;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class e implements com.quizlet.baserecyclerview.a {
    public final kotlinx.collections.immutable.b a;
    public final C0960p b;
    public final boolean c;
    public final z0 d;

    public e(kotlinx.collections.immutable.b recommendedTextbooks, C0960p onTextbookClick, boolean z, z0 onSearchClick) {
        Intrinsics.checkNotNullParameter(recommendedTextbooks, "recommendedTextbooks");
        Intrinsics.checkNotNullParameter(onTextbookClick, "onTextbookClick");
        Intrinsics.checkNotNullParameter(onSearchClick, "onSearchClick");
        this.a = recommendedTextbooks;
        this.b = onTextbookClick;
        this.c = z;
        this.d = onSearchClick;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return Intrinsics.b(this.a, eVar.a) && this.b.equals(eVar.b) && this.c == eVar.c && this.d.equals(eVar.d);
    }

    @Override // com.quizlet.baserecyclerview.a
    public final /* bridge */ /* synthetic */ Object getItemId() {
        return "questionDetailExtraInfoId";
    }

    public final int hashCode() {
        return this.d.hashCode() + d0.g((this.b.hashCode() + (this.a.hashCode() * 31)) * 31, 31, this.c);
    }

    public final String toString() {
        return "QuestionDetailExtraInfoState(recommendedTextbooks=" + this.a + ", onTextbookClick=" + this.b + ", isPlusUser=" + this.c + ", onSearchClick=" + this.d + ")";
    }
}
