package androidx.compose.material;

import com.google.android.gms.internal.mlkit_vision_barcode.Q4;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class X extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ float b;
    public final /* synthetic */ long c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ X(float f, int i, long j) {
        super(1);
        this.a = i;
        this.b = f;
        this.c = j;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                f0 f0Var = f0.a;
                ((AbstractC0581y) obj).getClass();
                throw null;
            case 1:
                androidx.compose.ui.graphics.drawscope.d dVar = (androidx.compose.ui.graphics.drawscope.d) obj;
                float f = this.b;
                float f2 = 2;
                dVar.C(this.c, Q4.c(DefinitionKt.NO_Float_VALUE, dVar.c0(f) / f2), Q4.c(androidx.compose.ui.geometry.e.d(dVar.g()), dVar.c0(f) / f2), dVar.c0(f), (496 & 16) != 0 ? 0 : 0);
                return Unit.a;
            default:
                androidx.compose.ui.graphics.drawscope.d dVar2 = (androidx.compose.ui.graphics.drawscope.d) obj;
                float f3 = this.b;
                float f4 = 2;
                dVar2.C(this.c, Q4.c(dVar2.c0(f3) / f4, DefinitionKt.NO_Float_VALUE), Q4.c(dVar2.c0(f3) / f4, androidx.compose.ui.geometry.e.b(dVar2.g())), dVar2.c0(f3), (496 & 16) != 0 ? 0 : 0);
                return Unit.a;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public X(float f, e0 e0Var, long j) {
        super(1);
        this.a = 0;
        this.b = f;
        this.c = j;
    }
}
