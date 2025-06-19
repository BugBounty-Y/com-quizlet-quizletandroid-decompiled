package androidx.compose.animation;

import com.google.android.gms.internal.mlkit_vision_barcode.P5;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class C extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.ui.layout.W b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C(androidx.compose.ui.layout.W w, int i) {
        super(1);
        this.a = i;
        this.b = w;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                androidx.compose.ui.layout.V.d((androidx.compose.ui.layout.V) obj, this.b, 0, 0);
                break;
            case 1:
                androidx.compose.ui.layout.V.d((androidx.compose.ui.layout.V) obj, this.b, 0, 0);
                break;
            case 2:
                androidx.compose.ui.layout.V.d((androidx.compose.ui.layout.V) obj, this.b, 0, 0);
                break;
            case 3:
                androidx.compose.ui.layout.V.f((androidx.compose.ui.layout.V) obj, this.b, 0, 0);
                break;
            case 4:
                androidx.compose.ui.layout.V.f((androidx.compose.ui.layout.V) obj, this.b, 0, 0);
                break;
            case 5:
                androidx.compose.ui.layout.V.f((androidx.compose.ui.layout.V) obj, this.b, 0, 0);
                break;
            case 6:
                androidx.compose.ui.layout.V v = (androidx.compose.ui.layout.V) obj;
                androidx.compose.ui.unit.k kVarB = v.b();
                androidx.compose.ui.unit.k kVar = androidx.compose.ui.unit.k.a;
                androidx.compose.ui.layout.W w = this.b;
                if (kVarB == kVar || v.c() == 0) {
                    androidx.compose.ui.layout.V.a(v, w);
                    w.s0(androidx.compose.ui.unit.h.d(0L, w.e), DefinitionKt.NO_Float_VALUE, null);
                } else {
                    int i = (int) 0;
                    long jB = P5.b((v.c() - w.a) - i, i);
                    androidx.compose.ui.layout.V.a(v, w);
                    w.s0(androidx.compose.ui.unit.h.d(jB, w.e), DefinitionKt.NO_Float_VALUE, null);
                }
                break;
            case 7:
                androidx.compose.ui.layout.V.f((androidx.compose.ui.layout.V) obj, this.b, 0, 0);
                break;
            case 8:
                androidx.compose.ui.layout.V.f((androidx.compose.ui.layout.V) obj, this.b, 0, 0);
                break;
            case 9:
                androidx.compose.ui.layout.V.d((androidx.compose.ui.layout.V) obj, this.b, 0, 0);
                break;
            case 10:
                androidx.compose.ui.layout.V.f((androidx.compose.ui.layout.V) obj, this.b, 0, 0);
                break;
            case 11:
                androidx.compose.ui.layout.V.d((androidx.compose.ui.layout.V) obj, this.b, 0, 0);
                break;
            case 12:
                androidx.compose.ui.layout.V.d((androidx.compose.ui.layout.V) obj, this.b, 0, 0);
                break;
            case 13:
                androidx.compose.ui.layout.V.f((androidx.compose.ui.layout.V) obj, this.b, 0, 0);
                break;
            case 14:
                androidx.compose.ui.layout.V.g((androidx.compose.ui.layout.V) obj, this.b, 0, 0);
                break;
            case 15:
                androidx.compose.ui.layout.V.f((androidx.compose.ui.layout.V) obj, this.b, 0, 0);
                break;
            default:
                androidx.compose.ui.layout.V layout = (androidx.compose.ui.layout.V) obj;
                Intrinsics.checkNotNullParameter(layout, "$this$layout");
                androidx.compose.ui.layout.V.f(layout, this.b, 0, 0);
                break;
        }
        return Unit.a;
    }
}
