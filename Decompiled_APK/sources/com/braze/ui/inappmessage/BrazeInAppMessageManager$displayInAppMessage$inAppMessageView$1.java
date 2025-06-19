package com.braze.ui.inappmessage;

import android.app.Activity;
import android.view.View;
import androidx.glance.appwidget.protobuf.Z;
import com.braze.models.inappmessage.IInAppMessage;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

@Metadata
@kotlin.coroutines.jvm.internal.e(c = "com.braze.ui.inappmessage.BrazeInAppMessageManager$displayInAppMessage$inAppMessageView$1", f = "BrazeInAppMessageManager.kt", l = {}, m = "invokeSuspend")
/* loaded from: classes.dex */
public final class BrazeInAppMessageManager$displayInAppMessage$inAppMessageView$1 extends i implements Function2<C, h<? super View>, Object> {
    final /* synthetic */ Activity $activity;
    final /* synthetic */ IInAppMessage $inAppMessage;
    final /* synthetic */ IInAppMessageViewFactory $inAppMessageViewFactory;
    int label;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public BrazeInAppMessageManager$displayInAppMessage$inAppMessageView$1(IInAppMessageViewFactory iInAppMessageViewFactory, Activity activity, IInAppMessage iInAppMessage, h<? super BrazeInAppMessageManager$displayInAppMessage$inAppMessageView$1> hVar) {
        super(2, hVar);
        this.$inAppMessageViewFactory = iInAppMessageViewFactory;
        this.$activity = activity;
        this.$inAppMessage = iInAppMessage;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h<Unit> create(Object obj, h<?> hVar) {
        return new BrazeInAppMessageManager$displayInAppMessage$inAppMessageView$1(this.$inAppMessageViewFactory, this.$activity, this.$inAppMessage, hVar);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        if (this.label != 0) {
            throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
        }
        Z.e(obj);
        return this.$inAppMessageViewFactory.createInAppMessageView(this.$activity, this.$inAppMessage);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(C c, h<? super View> hVar) {
        return ((BrazeInAppMessageManager$displayInAppMessage$inAppMessageView$1) create(c, hVar)).invokeSuspend(Unit.a);
    }
}
