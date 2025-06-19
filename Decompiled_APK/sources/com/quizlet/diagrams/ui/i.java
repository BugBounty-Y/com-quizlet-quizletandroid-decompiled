package com.quizlet.diagrams.ui;

import androidx.lifecycle.w0;
import java.util.LinkedHashSet;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes2.dex */
public final class i extends w0 {
    public final com.quizlet.data.repository.classfolder.e b;
    public final LinkedHashSet c;
    public final s0 d;

    public i(com.quizlet.data.repository.classfolder.e dataManager) {
        Intrinsics.checkNotNullParameter(dataManager, "dataManager");
        this.b = dataManager;
        this.c = new LinkedHashSet();
        this.d = e0.c(k.a);
    }
}
