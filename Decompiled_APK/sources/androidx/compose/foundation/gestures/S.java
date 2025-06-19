package androidx.compose.foundation.gestures;

import kotlin.Unit;

/* loaded from: classes.dex */
public final class S extends kotlin.coroutines.jvm.internal.i implements kotlin.jvm.functions.c {
    public final /* synthetic */ int j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ S(int i, int i2, kotlin.coroutines.h hVar) {
        super(i, hVar);
        this.j = i2;
    }

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        switch (this.j) {
            case 0:
                long j = ((androidx.compose.ui.geometry.b) obj2).a;
                return new S(3, 0, (kotlin.coroutines.h) obj3).invokeSuspend(Unit.a);
            case 1:
                ((Number) obj2).floatValue();
                return new S(3, 1, (kotlin.coroutines.h) obj3).invokeSuspend(Unit.a);
            case 2:
                long j2 = ((androidx.compose.ui.geometry.b) obj2).a;
                return new S(3, 2, (kotlin.coroutines.h) obj3).invokeSuspend(Unit.a);
            case 3:
                return new S(3, 3, (kotlin.coroutines.h) obj3).invokeSuspend(Unit.a);
            case 4:
                ((Number) obj).intValue();
                new S(3, 4, (kotlin.coroutines.h) obj3).invokeSuspend(Unit.a);
                return Boolean.FALSE;
            default:
                return new S(3, 5, (kotlin.coroutines.h) obj3).invokeSuspend(Unit.a);
        }
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        switch (this.j) {
            case 0:
                kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
                androidx.glance.appwidget.protobuf.Z.e(obj);
                return Unit.a;
            case 1:
                kotlin.coroutines.intrinsics.a aVar2 = kotlin.coroutines.intrinsics.a.a;
                androidx.glance.appwidget.protobuf.Z.e(obj);
                return Unit.a;
            case 2:
                kotlin.coroutines.intrinsics.a aVar3 = kotlin.coroutines.intrinsics.a.a;
                androidx.glance.appwidget.protobuf.Z.e(obj);
                return Unit.a;
            case 3:
                kotlin.coroutines.intrinsics.a aVar4 = kotlin.coroutines.intrinsics.a.a;
                androidx.glance.appwidget.protobuf.Z.e(obj);
                return Unit.a;
            case 4:
                kotlin.coroutines.intrinsics.a aVar5 = kotlin.coroutines.intrinsics.a.a;
                androidx.glance.appwidget.protobuf.Z.e(obj);
                return Boolean.FALSE;
            default:
                kotlin.coroutines.intrinsics.a aVar6 = kotlin.coroutines.intrinsics.a.a;
                androidx.glance.appwidget.protobuf.Z.e(obj);
                return Unit.a;
        }
    }
}
