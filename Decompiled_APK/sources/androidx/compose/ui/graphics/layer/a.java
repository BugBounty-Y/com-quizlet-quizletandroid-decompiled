package androidx.compose.ui.graphics.layer;

import androidx.compose.ui.graphics.C0861v;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class a extends r implements Function1 {
    public static final a b = new a(1, 0);
    public static final a c = new a(1, 1);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ a(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                break;
            default:
                androidx.compose.ui.graphics.drawscope.d.I((androidx.compose.ui.graphics.drawscope.d) obj, C0861v.f, 0L, 0L, DefinitionKt.NO_Float_VALUE, 126);
                break;
        }
        return Unit.a;
    }
}
