package androidx.compose.material;

import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class d0 extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.ui.unit.b b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ d0(androidx.compose.ui.unit.b bVar, int i) {
        super(0);
        this.a = i;
        this.b = bVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                return Float.valueOf(this.b.c0(Z.b));
            default:
                return Float.valueOf(this.b.c0(125));
        }
    }
}
