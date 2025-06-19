package com.skydoves.balloon;

import android.view.MotionEvent;
import android.view.View;
import kotlin.InterfaceC4938g;
import kotlin.Metadata;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.InterfaceC4953l;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class BalloonKt$sam$com_skydoves_balloon_OnBalloonOutsideTouchListener$0 implements OnBalloonOutsideTouchListener, InterfaceC4953l {
    private final /* synthetic */ Function2 function;

    public BalloonKt$sam$com_skydoves_balloon_OnBalloonOutsideTouchListener$0(Function2 function) {
        Intrinsics.checkNotNullParameter(function, "function");
        this.function = function;
    }

    public final boolean equals(Object obj) {
        if ((obj instanceof OnBalloonOutsideTouchListener) && (obj instanceof InterfaceC4953l)) {
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

    @Override // com.skydoves.balloon.OnBalloonOutsideTouchListener
    public final /* synthetic */ void onBalloonOutsideTouch(View view, MotionEvent motionEvent) {
        this.function.invoke(view, motionEvent);
    }
}
