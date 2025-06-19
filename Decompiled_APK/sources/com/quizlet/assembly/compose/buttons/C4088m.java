package com.quizlet.assembly.compose.buttons;

import androidx.compose.ui.graphics.C0861v;
import com.skydoves.balloon.internals.DefinitionKt;

/* renamed from: com.quizlet.assembly.compose.buttons.m, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4088m implements InterfaceC4092q {
    public final long a = new com.quizlet.themes.b(false, 3).o();

    @Override // com.quizlet.assembly.compose.buttons.InterfaceC4092q
    public final float a() {
        return DefinitionKt.NO_Float_VALUE;
    }

    @Override // com.quizlet.assembly.compose.buttons.InterfaceC4092q
    public final boolean b() {
        return false;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4088m) && C0861v.c(this.a, ((C4088m) obj).a);
    }

    public final int hashCode() {
        int i = C0861v.h;
        kotlin.C c = kotlin.D.b;
        return Long.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.B("Circular(color=", C0861v.i(this.a), ")");
    }
}
