package androidx.compose.foundation.lazy;

import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.animation.core.C0253l0;
import androidx.compose.animation.core.C0258o;
import androidx.glance.appwidget.protobuf.Z;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class y extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ A k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public y(A a, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = a;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new y(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((y) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            C0258o c0258o = this.k.w;
            Float f = new Float(DefinitionKt.NO_Float_VALUE);
            C0253l0 c0253l0Q = AbstractC0240f.q(1, new Float(0.5f));
            this.j = 1;
            if (AbstractC0240f.i(c0258o, f, c0253l0Q, true, null, this, 8) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}
