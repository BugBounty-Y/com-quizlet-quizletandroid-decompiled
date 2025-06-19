package androidx.compose.animation;

import com.google.android.gms.internal.mlkit_vision_barcode.R5;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class r extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ C0292t a;
    public final /* synthetic */ androidx.compose.ui.layout.W b;
    public final /* synthetic */ long c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public r(C0292t c0292t, androidx.compose.ui.layout.W w, long j) {
        super(1);
        this.a = c0292t;
        this.b = w;
        this.c = j;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        androidx.compose.ui.d dVar = this.a.b;
        androidx.compose.ui.layout.W w = this.b;
        androidx.compose.ui.layout.V.e((androidx.compose.ui.layout.V) obj, w, dVar.a(R5.a(w.a, w.b), this.c, androidx.compose.ui.unit.k.a));
        return Unit.a;
    }
}
