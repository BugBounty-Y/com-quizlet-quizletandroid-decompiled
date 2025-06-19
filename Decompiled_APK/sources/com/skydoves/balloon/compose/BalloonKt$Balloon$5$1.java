package com.skydoves.balloon.compose;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

@Metadata
@kotlin.coroutines.jvm.internal.e(c = "com.skydoves.balloon.compose.BalloonKt$Balloon$5$1", f = "Balloon.kt", l = {}, m = "invokeSuspend")
/* loaded from: classes3.dex */
public final class BalloonKt$Balloon$5$1 extends i implements Function2<C, h<? super Unit>, Object> {
    final /* synthetic */ BalloonComposeView $balloonComposeView;
    final /* synthetic */ Function1<BalloonWindow, Unit> $onBalloonWindowInitialized;
    int label;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public BalloonKt$Balloon$5$1(Function1<? super BalloonWindow, Unit> function1, BalloonComposeView balloonComposeView, h<? super BalloonKt$Balloon$5$1> hVar) {
        super(2, hVar);
        this.$onBalloonWindowInitialized = function1;
        this.$balloonComposeView = balloonComposeView;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h<Unit> create(Object obj, h<?> hVar) {
        return new BalloonKt$Balloon$5$1(this.$onBalloonWindowInitialized, this.$balloonComposeView, hVar);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        if (this.label != 0) {
            throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
        }
        Z.e(obj);
        this.$onBalloonWindowInitialized.invoke(this.$balloonComposeView);
        return Unit.a;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(C c, h<? super Unit> hVar) {
        return ((BalloonKt$Balloon$5$1) create(c, hVar)).invokeSuspend(Unit.a);
    }
}
