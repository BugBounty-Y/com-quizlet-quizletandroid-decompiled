package com.quizlet.features.home.viewmodel;

import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import com.quizlet.data.model.v2;
import com.quizlet.edgy.ui.viewmodel.C4203d;
import com.quizlet.features.home.data.s;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class c extends w0 implements d {
    public final com.quizlet.data.repository.classmembership.c b;
    public final com.lyft.android.scissors.b c;
    public final com.quizlet.features.home.logging.a d;
    public final com.quizlet.data.repository.user.a e;
    public final s0 f;
    public final d0 g;

    public c(com.quizlet.data.repository.classmembership.c getUserProfileAvatarDataUseCase, com.lyft.android.scissors.b getFeedUseCase, com.quizlet.features.home.logging.a homeEventLogger, com.quizlet.data.repository.user.a homeFeedShowProgress) {
        Intrinsics.checkNotNullParameter(getUserProfileAvatarDataUseCase, "getUserProfileAvatarDataUseCase");
        Intrinsics.checkNotNullParameter(getFeedUseCase, "getFeedUseCase");
        Intrinsics.checkNotNullParameter(homeEventLogger, "homeEventLogger");
        Intrinsics.checkNotNullParameter(homeFeedShowProgress, "homeFeedShowProgress");
        this.b = getUserProfileAvatarDataUseCase;
        this.c = getFeedUseCase;
        this.d = homeEventLogger;
        this.e = homeFeedShowProgress;
        this.f = e0.c(new s(v2.d, false));
        this.g = e0.b(0, 1, null, 5);
        E.A(p0.j(this), new C4203d(this), null, new b(this, null), 2);
    }
}
