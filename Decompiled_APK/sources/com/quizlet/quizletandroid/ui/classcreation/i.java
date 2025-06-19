package com.quizlet.quizletandroid.ui.classcreation;

import androidx.lifecycle.w0;
import com.quizlet.edgy.ui.viewmodel.C4203d;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class i extends w0 {
    public final com.quizlet.data.repository.folderwithcreatorinclass.e b;
    public final com.quizlet.offline.managers.b c;
    public final d0 d;
    public final d0 e;
    public final s0 f;
    public final C4203d g;

    public i(com.quizlet.data.repository.folderwithcreatorinclass.e createNewClassUseCase, com.quizlet.offline.managers.b offlineStateManager) {
        Intrinsics.checkNotNullParameter(createNewClassUseCase, "createNewClassUseCase");
        Intrinsics.checkNotNullParameter(offlineStateManager, "offlineStateManager");
        this.b = createNewClassUseCase;
        this.c = offlineStateManager;
        d0 d0VarB = e0.b(0, 0, null, 7);
        this.d = d0VarB;
        this.e = d0VarB;
        this.f = e0.c(com.quizlet.quizletandroid.ui.classcreation.data.g.a);
        this.g = new C4203d(this);
    }
}
