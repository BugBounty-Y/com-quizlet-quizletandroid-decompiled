package com.quizlet.explanations.textbook.tableofcontents.viewmodel;

import androidx.lifecycle.X;
import androidx.lifecycle.Y;
import com.quizlet.data.repository.folderset.c;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class b extends com.quizlet.viewmodel.a {
    public final com.quizlet.data.repository.widget.b d;
    public final c e;
    public final androidx.work.impl.model.c f;
    public final com.quizlet.time.b g;
    public final Y h;
    public final X i;
    public final Y j;
    public final Y k;
    public final X l;
    public final Y m;

    public b(com.quizlet.data.repository.widget.b getTextbookWithTOCUseCase, c saveMyRecentExplanationItemUseCase, androidx.work.impl.model.c userProperties) {
        com.quizlet.time.b timeProvider = com.quizlet.time.b.a;
        Intrinsics.checkNotNullParameter(getTextbookWithTOCUseCase, "getTextbookWithTOCUseCase");
        Intrinsics.checkNotNullParameter(saveMyRecentExplanationItemUseCase, "saveMyRecentExplanationItemUseCase");
        Intrinsics.checkNotNullParameter(userProperties, "userProperties");
        Intrinsics.checkNotNullParameter(timeProvider, "timeProvider");
        this.d = getTextbookWithTOCUseCase;
        this.e = saveMyRecentExplanationItemUseCase;
        this.f = userProperties;
        this.g = timeProvider;
        this.h = new Y();
        this.i = new X(1);
        this.j = new Y();
        this.k = new Y();
        this.l = new X(1);
        this.m = new Y();
    }
}
