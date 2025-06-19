package com.quizlet.features.match.studyengine;

import androidx.compose.foundation.text.input.internal.u;
import androidx.lifecycle.m0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f {
    public final com.google.android.material.floatingactionbutton.c a;
    public e b;

    public f(com.google.android.material.floatingactionbutton.c matchGameEngineFactory) {
        Intrinsics.checkNotNullParameter(matchGameEngineFactory, "matchGameEngineFactory");
        this.a = matchGameEngineFactory;
    }

    public final g a(m0 savedStateHandle) {
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        e eVar = this.b;
        if (eVar != null) {
            return eVar;
        }
        com.google.android.material.floatingactionbutton.c cVar = this.a;
        Intrinsics.checkNotNullParameter(savedStateHandle, "savedStateHandle");
        e eVar2 = new e(new b(((u) cVar.b).d(savedStateHandle)));
        this.b = eVar2;
        return eVar2;
    }
}
