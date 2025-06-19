package androidx.compose.foundation.pager;

import androidx.camera.camera2.internal.p0;
import androidx.compose.foundation.gestures.InterfaceC0334k0;
import androidx.compose.foundation.lazy.layout.X;
import androidx.compose.runtime.F0;
import androidx.compose.runtime.H0;
import androidx.compose.runtime.L0;
import androidx.glance.appwidget.protobuf.Z;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes.dex */
public final class C extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ C0466e k;
    public final /* synthetic */ int l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C(C0466e c0466e, int i, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = c0466e;
        this.l = i;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C) create((InterfaceC0334k0) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        C0466e c0466e = this.k;
        if (i == 0) {
            Z.e(obj);
            this.j = 1;
            Object objL = c0466e.w.l(this);
            if (objL != aVar) {
                objL = Unit.a;
            }
            if (objL == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        double d = DefinitionKt.NO_Float_VALUE;
        if (-0.5d > d || d > 0.5d) {
            throw new IllegalArgumentException("pageOffsetFraction 0.0 is not within the range -0.5 to 0.5".toString());
        }
        int i2 = c0466e.i(this.l);
        p0 p0Var = c0466e.c;
        ((H0) p0Var.d).j(i2);
        ((X) p0Var.f).a(i2);
        ((F0) p0Var.a).j(DefinitionKt.NO_Float_VALUE);
        p0Var.e = null;
        androidx.compose.ui.node.E e = (androidx.compose.ui.node.E) ((L0) c0466e.x).getValue();
        if (e != null) {
            e.k();
        }
        return Unit.a;
    }
}
