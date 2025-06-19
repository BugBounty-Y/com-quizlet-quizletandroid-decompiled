package com.quizlet.assembly.compose.buttons;

import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.assembly.compose.buttons.n, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4089n implements InterfaceC4092q {
    public final com.quizlet.explanations.textbook.ui.f a;

    public C4089n(com.quizlet.explanations.textbook.ui.f onEvent) {
        Intrinsics.checkNotNullParameter(onEvent, "onEvent");
        this.a = onEvent;
    }

    @Override // com.quizlet.assembly.compose.buttons.InterfaceC4092q
    public final float a() {
        return 1.0f;
    }

    @Override // com.quizlet.assembly.compose.buttons.InterfaceC4092q
    public final boolean b() {
        return true;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4089n)) {
            return false;
        }
        C4089n c4089n = (C4089n) obj;
        c4089n.getClass();
        return Float.compare(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE) == 0 && Float.compare(1.0f, 1.0f) == 0 && this.a.equals(c4089n.a);
    }

    public final int hashCode() {
        return this.a.hashCode() + androidx.compose.animation.d0.d(android.support.v4.media.session.a.b(Float.hashCode(DefinitionKt.NO_Float_VALUE) * 31, 1.0f, 31), 31, 8000L);
    }

    public final String toString() {
        return "LinearProgress(startProgress=0.0, endProgress=1.0, animationDurationMs=8000, onEvent=" + this.a + ")";
    }
}
