package androidx.compose.material3;

import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class C3 implements androidx.compose.ui.input.nestedscroll.a {
    public final /* synthetic */ F3 a;
    public final /* synthetic */ Function1 b;

    public C3(F3 f3, Function1 function1) {
        this.a = f3;
        this.b = function1;
    }

    @Override // androidx.compose.ui.input.nestedscroll.a
    public final long L(int i, long j) {
        float fE = androidx.compose.ui.geometry.b.e(j);
        if (fE >= DefinitionKt.NO_Float_VALUE || i != 1) {
            return 0L;
        }
        androidx.work.impl.model.t tVar = this.a.b;
        float fR = tVar.r(fE);
        float fK = Float.isNaN(tVar.k()) ? 0.0f : tVar.k();
        ((androidx.compose.runtime.F0) tVar.j).j(fR);
        return com.google.android.gms.internal.mlkit_vision_barcode.Q4.c(DefinitionKt.NO_Float_VALUE, fR - fK);
    }

    /* JADX WARN: Type inference failed for: r0v3, types: [java.lang.Object, java.util.Map] */
    @Override // androidx.compose.ui.input.nestedscroll.a
    public final Object i0(long j, kotlin.coroutines.h hVar) {
        float fC = androidx.compose.ui.unit.o.c(j);
        F3 f3 = this.a;
        float fS = f3.b.s();
        Float fZ = CollectionsKt.Z(f3.b.h().a.values());
        float fFloatValue = fZ != null ? fZ.floatValue() : Float.NaN;
        if (fC >= DefinitionKt.NO_Float_VALUE || fS <= fFloatValue) {
            j = 0;
        } else {
            this.b.invoke(new Float(fC));
        }
        return new androidx.compose.ui.unit.o(j);
    }

    @Override // androidx.compose.ui.input.nestedscroll.a
    public final Object p(long j, long j2, kotlin.coroutines.h hVar) {
        this.b.invoke(new Float(androidx.compose.ui.unit.o.c(j2)));
        return new androidx.compose.ui.unit.o(j2);
    }

    @Override // androidx.compose.ui.input.nestedscroll.a
    public final long s0(long j, long j2, int i) {
        if (i != 1) {
            return 0L;
        }
        androidx.work.impl.model.t tVar = this.a.b;
        float fR = tVar.r(androidx.compose.ui.geometry.b.e(j2));
        float fK = Float.isNaN(tVar.k()) ? 0.0f : tVar.k();
        ((androidx.compose.runtime.F0) tVar.j).j(fR);
        return com.google.android.gms.internal.mlkit_vision_barcode.Q4.c(DefinitionKt.NO_Float_VALUE, fR - fK);
    }
}
