package com.quizlet.login.recovery.forgotpassword.viewmodel;

import com.quizlet.api.IQuizletApiClient;
import io.reactivex.rxjava3.core.o;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;

@Metadata
/* loaded from: classes3.dex */
public final class e extends com.quizlet.viewmodel.b {
    public final IQuizletApiClient c;
    public final o d;
    public final o e;
    public final d0 f;

    public e(IQuizletApiClient apiClient, o networkScheduler, o mainThreadScheduler) {
        Intrinsics.checkNotNullParameter(apiClient, "apiClient");
        Intrinsics.checkNotNullParameter(networkScheduler, "networkScheduler");
        Intrinsics.checkNotNullParameter(mainThreadScheduler, "mainThreadScheduler");
        this.c = apiClient;
        this.d = networkScheduler;
        this.e = mainThreadScheduler;
        this.f = e0.b(0, 0, null, 7);
    }
}
