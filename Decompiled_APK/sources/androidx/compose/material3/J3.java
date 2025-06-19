package androidx.compose.material3;

import androidx.compose.animation.core.C0238e;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class J3 extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C0238e k;
    public final /* synthetic */ boolean l;
    public final /* synthetic */ androidx.compose.animation.core.K0 m;
    public final /* synthetic */ Function0 n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public J3(C0238e c0238e, boolean z, androidx.compose.animation.core.K0 k0, Function0 function0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c0238e;
        this.l = z;
        this.m = k0;
        this.n = function0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new J3(this.k, this.l, this.m, this.n, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((J3) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        J3 j3;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            Float f = new Float(this.l ? 1.0f : DefinitionKt.NO_Float_VALUE);
            this.j = 1;
            j3 = this;
            if (C0238e.c(this.k, f, this.m, null, j3, 12) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
            j3 = this;
        }
        j3.n.invoke();
        return Unit.a;
    }
}
