package androidx.compose.animation.core;

import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class L extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ float j;

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        L l = new L(2, hVar);
        l.j = ((Number) obj).floatValue();
        return l;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((L) create(Float.valueOf(((Number) obj).floatValue()), (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        return Boolean.valueOf(this.j > DefinitionKt.NO_Float_VALUE);
    }
}
