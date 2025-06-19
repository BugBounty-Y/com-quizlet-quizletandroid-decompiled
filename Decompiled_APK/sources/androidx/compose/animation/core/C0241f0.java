package androidx.compose.animation.core;

import androidx.compose.runtime.InterfaceC0773a0;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.animation.core.f0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0241f0 extends kotlin.coroutines.jvm.internal.i implements Function1 {
    public int j;
    public final /* synthetic */ C0247i0 k;
    public final /* synthetic */ Object l;
    public final /* synthetic */ E0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0241f0(C0247i0 c0247i0, E0 e0, Object obj, kotlin.coroutines.h hVar) {
        super(1, hVar);
        this.k = c0247i0;
        this.l = obj;
        this.m = e0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(kotlin.coroutines.h hVar) {
        Object obj = this.l;
        return new C0241f0(this.k, this.m, obj, hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((C0241f0) create((kotlin.coroutines.h) obj)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        E0 e0 = this.m;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            C0247i0 c0247i0 = this.k;
            c0247i0.Z();
            c0247i0.m = Long.MIN_VALUE;
            c0247i0.d0(DefinitionKt.NO_Float_VALUE);
            Object value = ((androidx.compose.runtime.L0) c0247i0.d).getValue();
            Object obj2 = this.l;
            boolean zEquals = obj2.equals(value);
            InterfaceC0773a0 interfaceC0773a0 = c0247i0.c;
            float f = zEquals ? -4.0f : obj2.equals(((androidx.compose.runtime.L0) interfaceC0773a0).getValue()) ? -5.0f : -3.0f;
            e0.r(obj2);
            e0.p(0L);
            ((androidx.compose.runtime.L0) interfaceC0773a0).setValue(obj2);
            c0247i0.d0(DefinitionKt.NO_Float_VALUE);
            c0247i0.L(obj2);
            e0.k(f);
            if (f == -3.0f) {
                this.j = 1;
                if (C0247i0.X(c0247i0, this) == aVar) {
                    return aVar;
                }
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        e0.j();
        return Unit.a;
    }
}
