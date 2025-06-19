package androidx.compose.foundation.text.selection;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3092a0;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class m0 extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.foundation.contextmenu.o b;
    public final /* synthetic */ i0 c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ m0(androidx.compose.foundation.contextmenu.o oVar, i0 i0Var, int i) {
        super(0);
        this.a = i;
        this.b = oVar;
        this.c = i0Var;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.c.f();
                AbstractC3092a0.a(this.b);
                break;
            case 1:
                this.c.d(false);
                AbstractC3092a0.a(this.b);
                break;
            case 2:
                this.c.n();
                AbstractC3092a0.a(this.b);
                break;
            default:
                this.c.o();
                AbstractC3092a0.a(this.b);
                break;
        }
        return Unit.a;
    }
}
