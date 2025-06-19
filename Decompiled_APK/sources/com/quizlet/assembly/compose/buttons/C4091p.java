package com.quizlet.assembly.compose.buttons;

import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.assembly.compose.buttons.p, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C4091p implements InterfaceC4092q {
    public final kotlinx.collections.immutable.e a;

    public C4091p(kotlinx.collections.immutable.e colors) {
        Intrinsics.checkNotNullParameter(colors, "colors");
        this.a = colors;
    }

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
        return (obj instanceof C4091p) && Intrinsics.b(this.a, ((C4091p) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Shimmer(colors=" + this.a + ")";
    }
}
