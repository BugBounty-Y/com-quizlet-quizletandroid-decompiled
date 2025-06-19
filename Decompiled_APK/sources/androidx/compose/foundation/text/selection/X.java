package androidx.compose.foundation.text.selection;

import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3092a0;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class X extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.foundation.contextmenu.o b;
    public final /* synthetic */ U c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ X(androidx.compose.foundation.contextmenu.o oVar, U u, int i) {
        super(0);
        this.a = i;
        this.b = oVar;
        this.c = u;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.c.b();
                AbstractC3092a0.a(this.b);
                break;
            default:
                this.c.k();
                AbstractC3092a0.a(this.b);
                break;
        }
        return Unit.a;
    }
}
