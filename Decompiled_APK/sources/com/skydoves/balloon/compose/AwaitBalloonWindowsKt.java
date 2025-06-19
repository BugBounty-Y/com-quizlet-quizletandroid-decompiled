package com.skydoves.balloon.compose;

import com.skydoves.balloon.Balloon;
import com.skydoves.balloon.DeferredBalloonGroup;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.jvm.functions.Function1;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class AwaitBalloonWindowsKt {
    public static final Object awaitBalloonWindows(@NotNull Function1<? super AwaitBalloonWindowsDsl, Unit> function1, @NotNull h<? super Unit> hVar) {
        AwaitBalloonWindowsDslImpl awaitBalloonWindowsDslImpl = new AwaitBalloonWindowsDslImpl();
        function1.invoke(awaitBalloonWindowsDslImpl);
        DeferredBalloonGroup deferredBalloonGroupBuild = awaitBalloonWindowsDslImpl.build();
        Balloon.Companion companion = Balloon.Companion;
        companion.initConsumerIfNeeded();
        Object objS = companion.getChannel().s(deferredBalloonGroupBuild, hVar);
        return objS == kotlin.coroutines.intrinsics.a.a ? objS : Unit.a;
    }
}
