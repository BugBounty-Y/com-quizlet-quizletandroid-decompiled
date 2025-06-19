package com.skydoves.balloon;

import android.content.Context;
import com.skydoves.balloon.Balloon;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class BalloonKt {
    @BalloonInlineDsl
    public static final /* synthetic */ Balloon createBalloon(Context context, Function1<? super Balloon.Builder, Unit> block) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(block, "block");
        Balloon.Builder builder = new Balloon.Builder(context);
        block.invoke(builder);
        return builder.build();
    }
}
