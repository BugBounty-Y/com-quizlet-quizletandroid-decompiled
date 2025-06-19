package com.skydoves.balloon;

import kotlin.InterfaceC4938g;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.InterfaceC4953l;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class BalloonKt$sam$com_skydoves_balloon_OnBalloonOverlayClickListener$0 implements OnBalloonOverlayClickListener, InterfaceC4953l {
    private final /* synthetic */ Function0 function;

    public BalloonKt$sam$com_skydoves_balloon_OnBalloonOverlayClickListener$0(Function0 function) {
        Intrinsics.checkNotNullParameter(function, "function");
        this.function = function;
    }

    public final boolean equals(Object obj) {
        if ((obj instanceof OnBalloonOverlayClickListener) && (obj instanceof InterfaceC4953l)) {
            return Intrinsics.b(getFunctionDelegate(), ((InterfaceC4953l) obj).getFunctionDelegate());
        }
        return false;
    }

    @Override // kotlin.jvm.internal.InterfaceC4953l
    @NotNull
    public final InterfaceC4938g getFunctionDelegate() {
        return this.function;
    }

    public final int hashCode() {
        return getFunctionDelegate().hashCode();
    }

    @Override // com.skydoves.balloon.OnBalloonOverlayClickListener
    public final /* synthetic */ void onBalloonOverlayClick() {
        this.function.invoke();
    }
}
