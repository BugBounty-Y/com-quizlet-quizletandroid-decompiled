package com.quizlet.features.folders.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.features.folders.data.S0;
import kotlin.Unit;

/* loaded from: classes3.dex */
public final class G extends kotlin.coroutines.jvm.internal.i implements kotlin.jvm.functions.c {
    public /* synthetic */ boolean j;
    public /* synthetic */ boolean k;

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        boolean zBooleanValue = ((Boolean) obj).booleanValue();
        boolean zBooleanValue2 = ((Boolean) obj2).booleanValue();
        G g = new G(3, (kotlin.coroutines.h) obj3);
        g.j = zBooleanValue;
        g.k = zBooleanValue2;
        return g.invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        return new S0(this.j, this.k);
    }
}
