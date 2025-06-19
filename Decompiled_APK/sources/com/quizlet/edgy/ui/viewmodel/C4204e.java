package com.quizlet.edgy.ui.viewmodel;

import androidx.lifecycle.w0;
import com.quizlet.data.model.Course;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;

@Metadata
/* renamed from: com.quizlet.edgy.ui.viewmodel.e, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4204e extends w0 {
    public final com.google.firebase.crashlytics.internal.settings.b b;
    public final com.onetrust.otpublishers.headless.UI.fragment.q c;
    public final d0 d;
    public Course e;
    public final C4203d f;

    public C4204e(com.google.firebase.crashlytics.internal.settings.b createNewCourseUseCase, com.onetrust.otpublishers.headless.UI.fragment.q getCourseUseCase) {
        Intrinsics.checkNotNullParameter(createNewCourseUseCase, "createNewCourseUseCase");
        Intrinsics.checkNotNullParameter(getCourseUseCase, "getCourseUseCase");
        this.b = createNewCourseUseCase;
        this.c = getCourseUseCase;
        this.d = e0.b(0, 0, null, 7);
        this.f = new C4203d(this);
    }
}
