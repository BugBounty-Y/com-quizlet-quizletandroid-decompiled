package androidx.compose.foundation.text.selection;

import androidx.compose.runtime.L0;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* renamed from: androidx.compose.foundation.text.selection.v, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0540v extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ U b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0540v(U u, int i) {
        super(0);
        this.a = i;
        this.b = u;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                androidx.compose.ui.geometry.b bVar = (androidx.compose.ui.geometry.b) ((L0) this.b.n).getValue();
                break;
            case 1:
                androidx.compose.ui.geometry.b bVar2 = (androidx.compose.ui.geometry.b) ((L0) this.b.o).getValue();
                break;
            case 2:
                U u = this.b;
                u.n(true);
                ((L0) u.p).setValue(null);
                ((L0) u.q).setValue(null);
                break;
            default:
                this.b.i();
                break;
        }
        return Unit.a;
    }
}
