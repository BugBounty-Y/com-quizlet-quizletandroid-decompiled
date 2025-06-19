package androidx.compose.material;

import androidx.compose.animation.core.AbstractC0240f;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;

/* renamed from: androidx.compose.material.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0560c extends kotlin.coroutines.jvm.internal.i implements kotlin.jvm.functions.d {
    public final /* synthetic */ int j;
    public int k;
    public /* synthetic */ Object l;
    public final /* synthetic */ float m;
    public /* synthetic */ Object n;
    public /* synthetic */ Object o;
    public final /* synthetic */ Object p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0560c(Object obj, float f, kotlin.coroutines.h hVar, int i) {
        super(4, hVar);
        this.j = i;
        this.p = obj;
        this.m = f;
    }

    @Override // kotlin.jvm.functions.d
    public final Object invoke(Object obj, Object obj2, Object obj3, Object obj4) {
        switch (this.j) {
            case 0:
                C0560c c0560c = new C0560c((C0575s) this.p, this.m, (kotlin.coroutines.h) obj4, 0);
                c0560c.n = (C0573p) obj;
                c0560c.o = (G) obj2;
                c0560c.l = obj3;
                return c0560c.invokeSuspend(Unit.a);
            default:
                C0560c c0560c2 = new C0560c((androidx.work.impl.model.t) this.p, this.m, (kotlin.coroutines.h) obj4, 1);
                c0560c2.n = (androidx.compose.material3.internal.r) obj;
                c0560c2.o = (androidx.compose.material3.internal.F) obj2;
                c0560c2.l = obj3;
                return c0560c2.invokeSuspend(Unit.a);
        }
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        switch (this.j) {
            case 0:
                kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
                int i = this.k;
                if (i == 0) {
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    C0573p c0573p = (C0573p) this.n;
                    float fC = ((G) this.o).c(this.l);
                    if (!Float.isNaN(fC)) {
                        kotlin.jvm.internal.G g = new kotlin.jvm.internal.G();
                        C0575s c0575s = (C0575s) this.p;
                        float fE = Float.isNaN(c0575s.e()) ? DefinitionKt.NO_Float_VALUE : c0575s.e();
                        g.a = fE;
                        float f = fE;
                        androidx.compose.foundation.contextmenu.i iVar = new androidx.compose.foundation.contextmenu.i(10, c0573p, g);
                        this.n = null;
                        this.o = null;
                        this.k = 1;
                        if (AbstractC0240f.c(f, fC, this.m, c0575s.c, iVar, this) == aVar) {
                            return aVar;
                        }
                    }
                } else {
                    if (i != 1) {
                        throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                    }
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                }
                return Unit.a;
            default:
                kotlin.coroutines.intrinsics.a aVar2 = kotlin.coroutines.intrinsics.a.a;
                int i2 = this.k;
                if (i2 == 0) {
                    androidx.glance.appwidget.protobuf.Z.e(obj);
                    androidx.compose.material3.internal.r rVar = (androidx.compose.material3.internal.r) this.n;
                    float fC2 = ((androidx.compose.material3.internal.F) this.o).c(this.l);
                    if (!Float.isNaN(fC2)) {
                        kotlin.jvm.internal.G g2 = new kotlin.jvm.internal.G();
                        androidx.work.impl.model.t tVar = (androidx.work.impl.model.t) this.p;
                        float fK = Float.isNaN(tVar.k()) ? DefinitionKt.NO_Float_VALUE : tVar.k();
                        g2.a = fK;
                        androidx.compose.foundation.contextmenu.i iVar2 = new androidx.compose.foundation.contextmenu.i(21, rVar, g2);
                        this.n = null;
                        this.o = null;
                        this.k = 1;
                        if (AbstractC0240f.c(fK, fC2, this.m, (androidx.compose.animation.core.D) tVar.c, iVar2, this) == aVar2) {
                            return aVar2;
                        }
                    }
                    return Unit.a;
                }
                if (i2 != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                androidx.glance.appwidget.protobuf.Z.e(obj);
                return Unit.a;
        }
    }
}
