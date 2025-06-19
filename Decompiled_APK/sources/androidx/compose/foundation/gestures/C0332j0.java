package androidx.compose.foundation.gestures;

import androidx.compose.animation.core.AbstractC0240f;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: androidx.compose.foundation.gestures.j0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0332j0 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ float l;
    public final /* synthetic */ androidx.compose.animation.core.K0 m;
    public final /* synthetic */ kotlin.jvm.internal.G n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0332j0(float f, androidx.compose.animation.core.K0 k0, kotlin.jvm.internal.G g, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = f;
        this.m = k0;
        this.n = g;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C0332j0 c0332j0 = new C0332j0(this.l, this.m, this.n, hVar);
        c0332j0.k = obj;
        return c0332j0;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C0332j0) create((InterfaceC0334k0) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            C0330i0 c0330i0 = new C0330i0(this.n, (InterfaceC0334k0) this.k, 0);
            this.j = 1;
            if (AbstractC0240f.e(DefinitionKt.NO_Float_VALUE, this.l, this.m, c0330i0, this, 4) == aVar) {
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
