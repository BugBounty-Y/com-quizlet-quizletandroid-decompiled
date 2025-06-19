package com.quizlet.login.resetpassword.viewmodel;

import androidx.lifecycle.w0;
import androidx.work.impl.model.e;
import com.quizlet.login.resetpassword.data.g;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class c extends w0 implements a {
    public final e b;
    public final s0 c;
    public final d0 d;

    public c(e resetPasswordUseCase) {
        Intrinsics.checkNotNullParameter(resetPasswordUseCase, "resetPasswordUseCase");
        this.b = resetPasswordUseCase;
        this.c = e0.c(new g(null, false));
        this.d = e0.b(0, 1, null, 5);
    }
}
