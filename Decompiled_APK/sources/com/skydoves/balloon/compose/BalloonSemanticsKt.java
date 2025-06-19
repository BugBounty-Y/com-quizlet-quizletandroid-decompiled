package com.skydoves.balloon.compose;

import androidx.compose.ui.semantics.k;
import androidx.compose.ui.semantics.u;
import androidx.compose.ui.semantics.v;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class BalloonSemanticsKt {

    @NotNull
    private static final u IsBalloon = new u("IsBalloon", new g());

    /* JADX INFO: Access modifiers changed from: private */
    public static final Unit IsBalloon$lambda$0(Unit unit, Unit unit2) {
        Intrinsics.checkNotNullParameter(unit2, "<unused var>");
        throw new IllegalStateException("merge function called on unmergeable property IsBalloon. A dialog should not be a child of a clickable/focusable node.");
    }

    public static final void balloon(@NotNull v vVar) {
        Intrinsics.checkNotNullParameter(vVar, "<this>");
        ((k) vVar).b(IsBalloon, Unit.a);
    }

    @NotNull
    public static final u getIsBalloon() {
        return IsBalloon;
    }
}
