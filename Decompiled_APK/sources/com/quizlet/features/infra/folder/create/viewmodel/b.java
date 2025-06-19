package com.quizlet.features.infra.folder.create.viewmodel;

import androidx.lifecycle.w0;
import com.google.android.gms.measurement.internal.J;
import com.quizlet.eventlogger.EventLogger;
import com.quizlet.features.infra.folder.create.data.e;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class b extends w0 {
    public final J b;
    public final EventLogger c;
    public final s0 d;

    public b(J createFolderUseCase, EventLogger eventLogger) {
        Intrinsics.checkNotNullParameter(createFolderUseCase, "createFolderUseCase");
        Intrinsics.checkNotNullParameter(eventLogger, "eventLogger");
        this.b = createFolderUseCase;
        this.c = eventLogger;
        this.d = e0.c(e.a);
    }
}
