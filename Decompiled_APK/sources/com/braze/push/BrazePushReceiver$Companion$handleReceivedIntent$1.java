package com.braze.push;

import android.content.Context;
import android.content.Intent;
import androidx.glance.appwidget.protobuf.Z;
import com.braze.push.BrazePushReceiver;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

@Metadata
@kotlin.coroutines.jvm.internal.e(c = "com.braze.push.BrazePushReceiver$Companion$handleReceivedIntent$1", f = "BrazePushReceiver.kt", l = {}, m = "invokeSuspend")
/* loaded from: classes.dex */
public final class BrazePushReceiver$Companion$handleReceivedIntent$1 extends kotlin.coroutines.jvm.internal.i implements Function2<C, kotlin.coroutines.h<? super Unit>, Object> {
    final /* synthetic */ Context $context;
    final /* synthetic */ Intent $intent;
    int label;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public BrazePushReceiver$Companion$handleReceivedIntent$1(Context context, Intent intent, kotlin.coroutines.h<? super BrazePushReceiver$Companion$handleReceivedIntent$1> hVar) {
        super(2, hVar);
        this.$context = context;
        this.$intent = intent;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h<Unit> create(Object obj, kotlin.coroutines.h<?> hVar) {
        return new BrazePushReceiver$Companion$handleReceivedIntent$1(this.$context, this.$intent, hVar);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        if (this.label != 0) {
            throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
        }
        Z.e(obj);
        BrazePushReceiver.Companion companion = BrazePushReceiver.Companion;
        Context applicationContext = this.$context.getApplicationContext();
        Intrinsics.checkNotNullExpressionValue(applicationContext, "getApplicationContext(...)");
        companion.handlePush(applicationContext, this.$intent);
        return Unit.a;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(C c, kotlin.coroutines.h<? super Unit> hVar) {
        return ((BrazePushReceiver$Companion$handleReceivedIntent$1) create(c, hVar)).invokeSuspend(Unit.a);
    }
}
