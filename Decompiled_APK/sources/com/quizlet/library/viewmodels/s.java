package com.quizlet.library.viewmodels;

import androidx.lifecycle.p0;
import com.quizlet.edgy.ui.viewmodel.C4203d;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class s extends com.quizlet.viewmodel.a {
    public final com.quizlet.data.repository.explanations.myexplanations.a d;
    public final s0 e;

    public s(com.quizlet.data.repository.explanations.myexplanations.a getMyExplanationsUseCase) {
        Intrinsics.checkNotNullParameter(getMyExplanationsUseCase, "getMyExplanationsUseCase");
        this.d = getMyExplanationsUseCase;
        this.e = e0.c(o.a);
        E.A(p0.j(this), new C4203d(this), null, new q(this, null), 2);
    }
}
