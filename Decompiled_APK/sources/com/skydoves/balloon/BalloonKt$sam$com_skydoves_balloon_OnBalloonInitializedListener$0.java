package com.skydoves.balloon;

import android.view.View;
import kotlin.InterfaceC4938g;
import kotlin.Metadata;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.InterfaceC4953l;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class BalloonKt$sam$com_skydoves_balloon_OnBalloonInitializedListener$0 implements OnBalloonInitializedListener, InterfaceC4953l {
    private final /* synthetic */ Function1 function;

    public BalloonKt$sam$com_skydoves_balloon_OnBalloonInitializedListener$0(Function1 function) {
        Intrinsics.checkNotNullParameter(function, "function");
        this.function = function;
    }

    public final boolean equals(Object obj) {
        if ((obj instanceof OnBalloonInitializedListener) && (obj instanceof InterfaceC4953l)) {
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

    @Override // com.skydoves.balloon.OnBalloonInitializedListener
    public final /* synthetic */ void onBalloonInitialized(View view) {
        this.function.invoke(view);
    }
}
