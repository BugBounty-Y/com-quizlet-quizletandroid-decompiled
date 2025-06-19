package androidx.compose.animation.core;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.animation.core.d0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0237d0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ Object l;
    public final /* synthetic */ Object m;
    public final /* synthetic */ C0247i0 n;
    public final /* synthetic */ E0 o;
    public final /* synthetic */ float p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0237d0(Object obj, Object obj2, C0247i0 c0247i0, E0 e0, float f, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = obj;
        this.m = obj2;
        this.n = c0247i0;
        this.o = e0;
        this.p = f;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0237d0 c0237d0 = new C0237d0(this.l, this.m, this.n, this.o, this.p, hVar);
        c0237d0.k = obj;
        return c0237d0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0237d0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        C0247i0 c0247i0 = this.n;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            kotlinx.coroutines.C c = (kotlinx.coroutines.C) this.k;
            Object obj2 = this.l;
            Object obj3 = this.m;
            if (Intrinsics.b(obj2, obj3)) {
                c0247i0.o = null;
                if (Intrinsics.b(((androidx.compose.runtime.L0) c0247i0.d).getValue(), obj2)) {
                    return Unit.a;
                }
            } else {
                C0247i0.T(c0247i0);
            }
            boolean zB = Intrinsics.b(obj2, obj3);
            float f = this.p;
            if (!zB) {
                E0 e0 = this.o;
                e0.r(obj2);
                e0.p(0L);
                ((androidx.compose.runtime.L0) c0247i0.c).setValue(obj2);
                e0.k(f);
            }
            c0247i0.d0(f);
            if (c0247i0.n.b != 0) {
                kotlinx.coroutines.E.A(c, null, null, new C0235c0(c0247i0, null), 3);
            } else {
                c0247i0.m = Long.MIN_VALUE;
            }
            this.j = 1;
            if (C0247i0.X(c0247i0, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        c0247i0.c0();
        return Unit.a;
    }
}
