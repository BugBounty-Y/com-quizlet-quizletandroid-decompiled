package androidx.compose.animation.core;

import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C5028l;

/* loaded from: classes.dex */
public final class G0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public kotlinx.coroutines.sync.c j;
    public J0 k;
    public int l;
    public final /* synthetic */ J0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public G0(J0 j0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.m = j0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new G0(this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((G0) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Type inference failed for: r3v0, types: [java.lang.Object, kotlin.k] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlinx.coroutines.sync.c cVar;
        J0 j0;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.l;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            J0 j02 = this.m;
            C0247i0 c0247i0 = (C0247i0) j02;
            c0247i0.getClass();
            ((androidx.compose.runtime.snapshots.v) I0.a.getValue()).d(c0247i0, C0266s0.d, c0247i0.h);
            cVar = c0247i0.k;
            this.j = cVar;
            this.k = j02;
            this.l = 1;
            if (cVar.d(this) == aVar) {
                return aVar;
            }
            j0 = j02;
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            j0 = this.k;
            cVar = this.j;
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        try {
            ((C0247i0) j0).e = j0.I();
            C5028l c5028l = ((C0247i0) j0).j;
            if (c5028l != null) {
                kotlin.p pVar = kotlin.r.b;
                c5028l.resumeWith(j0.I());
            }
            ((C0247i0) j0).j = null;
            Unit unit = Unit.a;
            cVar.f(null);
            return Unit.a;
        } catch (Throwable th) {
            cVar.f(null);
            throw th;
        }
    }
}
