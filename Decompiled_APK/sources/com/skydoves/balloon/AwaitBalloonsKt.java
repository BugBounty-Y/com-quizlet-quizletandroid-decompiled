package com.skydoves.balloon;

import com.skydoves.balloon.Balloon;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.jvm.functions.Function1;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class AwaitBalloonsKt {
    public static final Object awaitBalloons(@NotNull Function1<? super AwaitBalloonsDsl, Unit> function1, @NotNull h<? super Unit> hVar) {
        AwaitBalloonsDslImpl awaitBalloonsDslImpl = new AwaitBalloonsDslImpl();
        function1.invoke(awaitBalloonsDslImpl);
        DeferredBalloonGroup deferredBalloonGroupBuild = awaitBalloonsDslImpl.build();
        Balloon.Companion companion = Balloon.Companion;
        companion.initConsumerIfNeeded();
        Object objS = companion.getChannel().s(deferredBalloonGroupBuild, hVar);
        return objS == kotlin.coroutines.intrinsics.a.a ? objS : Unit.a;
    }
}
