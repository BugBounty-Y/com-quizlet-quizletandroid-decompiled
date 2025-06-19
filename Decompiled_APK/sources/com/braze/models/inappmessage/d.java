package com.braze.models.inappmessage;

import androidx.glance.appwidget.protobuf.Z;
import com.braze.events.internal.f0;
import com.braze.managers.C1500m;
import com.braze.managers.c0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class d extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ InAppMessageBase a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(InAppMessageBase inAppMessageBase, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.a = inAppMessageBase;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new d(this.a, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return new d(this.a, (kotlin.coroutines.h) obj2).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        c0 brazeManager;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        if (this.a.clickLogged.get() && (brazeManager = this.a.getBrazeManager()) != null) {
            com.braze.triggers.events.d triggerEvent = new com.braze.triggers.events.d(this.a.getTriggerId());
            Intrinsics.checkNotNullParameter(triggerEvent, "triggerEvent");
            ((C1500m) brazeManager).d.b(new f0(triggerEvent), f0.class);
        }
        return Unit.a;
    }
}
