package androidx.compose.ui.window;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.I;

/* loaded from: classes.dex */
public final class t extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ I a;
    public final /* synthetic */ u b;
    public final /* synthetic */ androidx.compose.ui.unit.i c;
    public final /* synthetic */ long d;
    public final /* synthetic */ long e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public t(I i, u uVar, androidx.compose.ui.unit.i iVar, long j, long j2) {
        super(0);
        this.a = i;
        this.b = uVar;
        this.c = iVar;
        this.d = j;
        this.e = j2;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        u uVar = this.b;
        x positionProvider = uVar.getPositionProvider();
        androidx.compose.ui.unit.k parentLayoutDirection = uVar.getParentLayoutDirection();
        this.a.a = positionProvider.a(this.c, this.d, parentLayoutDirection, this.e);
        return Unit.a;
    }
}
