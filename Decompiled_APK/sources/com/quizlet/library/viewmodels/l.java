package com.quizlet.library.viewmodels;

import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import com.quizlet.edgy.ui.viewmodel.C4203d;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class l extends w0 {
    public final com.quizlet.data.interactor.course.e b;
    public final androidx.work.impl.model.e c;
    public final s0 d;

    public l(com.quizlet.data.interactor.course.e getPracticeTestsListUseCase, androidx.work.impl.model.e practiceTestUploadFeature) {
        Intrinsics.checkNotNullParameter(getPracticeTestsListUseCase, "getPracticeTestsListUseCase");
        Intrinsics.checkNotNullParameter(practiceTestUploadFeature, "practiceTestUploadFeature");
        this.b = getPracticeTestsListUseCase;
        this.c = practiceTestUploadFeature;
        this.d = e0.c(h.a);
        E.A(p0.j(this), new C4203d(this), null, new j(this, null), 2);
    }
}
