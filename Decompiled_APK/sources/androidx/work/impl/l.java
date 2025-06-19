package androidx.work.impl;

import android.content.Context;
import androidx.glance.appwidget.protobuf.Z;
import androidx.work.impl.background.systemalarm.RescheduleReceiver;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class l extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ boolean j;
    public final /* synthetic */ Context k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public l(Context context, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = context;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        l lVar = new l(this.k, hVar);
        lVar.j = ((Boolean) obj).booleanValue();
        return lVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        Boolean bool = (Boolean) obj;
        bool.booleanValue();
        return ((l) create(bool, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        androidx.work.impl.utils.h.a(this.k, RescheduleReceiver.class, this.j);
        return Unit.a;
    }
}
