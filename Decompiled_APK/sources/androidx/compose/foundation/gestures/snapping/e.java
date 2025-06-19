package androidx.compose.foundation.gestures.snapping;

import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.animation.core.C0253l0;
import androidx.compose.animation.core.C0258o;
import androidx.compose.animation.core.C0276z;
import androidx.compose.animation.core.F;
import androidx.compose.animation.core.L0;
import androidx.compose.animation.core.M0;
import androidx.compose.foundation.gestures.G0;
import androidx.glance.appwidget.protobuf.Z;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.G;
import kotlin.jvm.internal.r;
import kotlinx.coroutines.C;

/* loaded from: classes.dex */
public final class e extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public G j;
    public int k;
    public final /* synthetic */ h l;
    public final /* synthetic */ float m;
    public final /* synthetic */ r n;
    public final /* synthetic */ G0 o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public e(h hVar, float f, Function1 function1, G0 g0, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.l = hVar;
        this.m = f;
        this.n = (r) function1;
        this.o = g0;
    }

    /* JADX WARN: Type inference failed for: r3v0, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new e(this.l, this.m, this.n, this.o, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    /* JADX WARN: Type inference failed for: r6v0, types: [kotlin.jvm.functions.Function1, kotlin.jvm.internal.r] */
    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        G g;
        Object objB;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.k;
        ?? r6 = this.n;
        h hVar = this.l;
        if (i == 0) {
            Z.e(obj);
            C0276z c0276z = hVar.b;
            L0 l0 = M0.a;
            F f = c0276z.a;
            float f2 = this.m;
            float fH = hVar.a.h(f2, f.r(DefinitionKt.NO_Float_VALUE, f2));
            if (Float.isNaN(fH)) {
                throw new IllegalStateException("calculateApproachOffset returned NaN. Please use a valid value.");
            }
            g = new G();
            float fSignum = Math.signum(f2) * Math.abs(fH);
            g.a = fSignum;
            r6.invoke(new Float(fSignum));
            float f3 = g.a;
            d dVar = new d(g, r6, 1);
            this.j = g;
            this.k = 1;
            objB = h.b(this.l, this.o, f3, this.m, dVar, this);
            if (objB != aVar) {
            }
        }
        if (i != 1) {
            if (i != 2) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            return obj;
        }
        G g2 = this.j;
        Z.e(obj);
        g = g2;
        objB = obj;
        C0258o c0258o = (C0258o) objB;
        float fJ = hVar.a.j(((Number) c0258o.a()).floatValue());
        if (Float.isNaN(fJ)) {
            throw new IllegalStateException("calculateSnapOffset returned NaN. Please use a valid value.");
        }
        g.a = fJ;
        C0258o c0258oL = AbstractC0240f.l(c0258o, DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE, 30);
        C0253l0 c0253l0 = hVar.c;
        d dVar2 = new d(g, r6, 0);
        this.j = null;
        this.k = 2;
        Object objB2 = l.b(this.o, fJ, fJ, c0258oL, c0253l0, dVar2, this);
        return objB2 == aVar ? aVar : objB2;
    }
}
