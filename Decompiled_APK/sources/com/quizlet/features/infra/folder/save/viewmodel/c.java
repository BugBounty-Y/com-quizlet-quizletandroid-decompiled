package com.quizlet.features.infra.folder.save.viewmodel;

import androidx.compose.foundation.gestures.l1;
import androidx.lifecycle.p0;
import androidx.lifecycle.w0;
import com.quizlet.eventlogger.features.folder.FolderLogger;
import com.quizlet.generated.enums.y1;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

@Metadata
/* loaded from: classes3.dex */
public final class c extends w0 {
    public final l1 b;
    public final FolderLogger c;
    public y1 d;
    public String e;
    public final s0 f;

    public c(l1 getIfMaterialIsInAnyFolderUseCase, FolderLogger folderEventLogger) {
        Intrinsics.checkNotNullParameter(getIfMaterialIsInAnyFolderUseCase, "getIfMaterialIsInAnyFolderUseCase");
        Intrinsics.checkNotNullParameter(folderEventLogger, "folderEventLogger");
        this.b = getIfMaterialIsInAnyFolderUseCase;
        this.c = folderEventLogger;
        this.e = "";
        this.f = e0.c(com.quizlet.features.infra.folder.save.screenstates.b.a);
    }

    public final void A() {
        y1 y1Var = this.d;
        if (y1Var == null) {
            return;
        }
        String str = this.e;
        if (str.length() == 0) {
            return;
        }
        E.A(p0.j(this), null, null, new b(this, y1Var, str, null), 3);
    }
}
