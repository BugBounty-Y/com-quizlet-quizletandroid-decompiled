package androidx.compose.foundation.gestures;

import androidx.compose.animation.core.AbstractC0240f;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.gestures.r0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0347r0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ L0 l;
    public final /* synthetic */ long m;
    public final /* synthetic */ kotlin.jvm.internal.G n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0347r0(L0 l0, long j, kotlin.jvm.internal.G g, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = l0;
        this.m = j;
        this.n = g;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0347r0 c0347r0 = new C0347r0(this.l, this.m, this.n, hVar);
        c0347r0.k = obj;
        return c0347r0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0347r0) create((I0) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            I0 i0 = (I0) this.k;
            L0 l0 = this.l;
            float f = l0.f(this.m);
            C0346q0 c0346q0 = new C0346q0(this.n, l0, i0, 0);
            this.j = 1;
            if (AbstractC0240f.e(DefinitionKt.NO_Float_VALUE, f, null, c0346q0, this, 12) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        return Unit.a;
    }
}
