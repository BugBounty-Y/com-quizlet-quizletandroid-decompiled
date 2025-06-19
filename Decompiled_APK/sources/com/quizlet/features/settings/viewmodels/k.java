package com.quizlet.features.settings.viewmodels;

import androidx.lifecycle.m0;
import androidx.lifecycle.w0;
import com.quizlet.edgy.ui.viewmodel.C4203d;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class k extends w0 implements n {
    public final com.onetrust.otpublishers.headless.UI.fragment.q b;
    public final s0 c;
    public final d0 d;
    public final C4203d e;

    public k(m0 savedStateHandle, com.onetrust.otpublishers.headless.UI.fragment.q deleteUserAccountUseCase) {
        Object obj;
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        Intrinsics.checkNotNullParameter(deleteUserAccountUseCase, "deleteUserAccountUseCase");
        this.b = deleteUserAccountUseCase;
        String str = (String) savedStateHandle.a("reauthType");
        int iOrdinal = com.quizlet.features.settings.data.models.f.valueOf(str == null ? "Password" : str).ordinal();
        if (iOrdinal == 0) {
            obj = com.quizlet.features.settings.data.states.p.a;
        } else if (iOrdinal == 1) {
            obj = com.quizlet.features.settings.data.states.q.a;
        } else {
            if (iOrdinal != 2) {
                throw new NoWhenBranchMatchedException();
            }
            obj = com.quizlet.features.settings.data.states.o.a;
        }
        this.c = e0.c(obj);
        this.d = e0.b(0, 1, null, 5);
        this.e = new C4203d(this);
    }
}
