package androidx.compose.material.ripple;

import androidx.compose.animation.core.C0238e;
import androidx.compose.animation.core.K0;
import androidx.glance.appwidget.protobuf.Z;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public final class q extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ r k;
    public final /* synthetic */ K0 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public q(r rVar, K0 k0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = rVar;
        this.l = k0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new q(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((q) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            C0238e c0238e = (C0238e) this.k.c;
            Float f = new Float(DefinitionKt.NO_Float_VALUE);
            this.j = 1;
            if (C0238e.c(c0238e, f, this.l, null, this, 12) == aVar) {
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
