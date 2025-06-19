package androidx.compose.material3;

import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class D3 extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ boolean a;
    public final /* synthetic */ androidx.compose.ui.unit.b b;
    public final /* synthetic */ G3 c;
    public final /* synthetic */ Function1 d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public D3(boolean z, androidx.compose.ui.unit.b bVar, G3 g3, Function1 function1) {
        super(0);
        this.a = z;
        this.b = bVar;
        this.c = g3;
        this.d = function1;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        return new F3(this.a, this.b, this.c, this.d);
    }
}
