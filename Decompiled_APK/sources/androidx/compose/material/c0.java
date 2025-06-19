package androidx.compose.material;

import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class c0 extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.ui.unit.b b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ c0(androidx.compose.ui.unit.b bVar, int i) {
        super(1);
        this.a = i;
        this.b = bVar;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                ((Number) obj).floatValue();
                return Float.valueOf(this.b.c0(Z.a));
            default:
                ((Number) obj).floatValue();
                return Float.valueOf(this.b.c0(56));
        }
    }
}
