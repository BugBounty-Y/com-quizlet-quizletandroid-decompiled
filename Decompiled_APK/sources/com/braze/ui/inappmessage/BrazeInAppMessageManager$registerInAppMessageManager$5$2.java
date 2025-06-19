package com.braze.ui.inappmessage;

import androidx.glance.appwidget.protobuf.Z;
import com.braze.models.inappmessage.IInAppMessage;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

@Metadata
@kotlin.coroutines.jvm.internal.e(c = "com.braze.ui.inappmessage.BrazeInAppMessageManager$registerInAppMessageManager$5$2", f = "BrazeInAppMessageManager.kt", l = {248}, m = "invokeSuspend")
/* loaded from: classes.dex */
public final class BrazeInAppMessageManager$registerInAppMessageManager$5$2 extends i implements Function2<C, h<? super Unit>, Object> {
    final /* synthetic */ IInAppMessage $it;
    int label;
    final /* synthetic */ BrazeInAppMessageManager this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public BrazeInAppMessageManager$registerInAppMessageManager$5$2(BrazeInAppMessageManager brazeInAppMessageManager, IInAppMessage iInAppMessage, h<? super BrazeInAppMessageManager$registerInAppMessageManager$5$2> hVar) {
        super(2, hVar);
        this.this$0 = brazeInAppMessageManager;
        this.$it = iInAppMessage;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h<Unit> create(Object obj, h<?> hVar) {
        return new BrazeInAppMessageManager$registerInAppMessageManager$5$2(this.this$0, this.$it, hVar);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.label;
        if (i == 0) {
            Z.e(obj);
            BrazeInAppMessageManager brazeInAppMessageManager = this.this$0;
            IInAppMessage iInAppMessage = this.$it;
            this.label = 1;
            if (brazeInAppMessageManager.displayInAppMessage(iInAppMessage, true, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(C c, h<? super Unit> hVar) {
        return ((BrazeInAppMessageManager$registerInAppMessageManager$5$2) create(c, hVar)).invokeSuspend(Unit.a);
    }
}
