package androidx.compose.ui.window;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* loaded from: classes.dex */
public final class g extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ u a;
    public final /* synthetic */ Function0 b;
    public final /* synthetic */ y c;
    public final /* synthetic */ String d;
    public final /* synthetic */ androidx.compose.ui.unit.k e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(u uVar, Function0 function0, y yVar, String str, androidx.compose.ui.unit.k kVar) {
        super(0);
        this.a = uVar;
        this.b = function0;
        this.c = yVar;
        this.d = str;
        this.e = kVar;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        this.a.f(this.b, this.c, this.d, this.e);
        return Unit.a;
    }
}
