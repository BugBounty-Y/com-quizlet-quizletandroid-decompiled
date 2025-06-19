package androidx.compose.animation.core;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;

/* renamed from: androidx.compose.animation.core.p0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0261p0 extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ C0258o b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0261p0(int i, C0258o c0258o) {
        super(0);
        this.a = i;
        this.b = c0258o;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                this.b.f = false;
                return Unit.a;
            case 1:
                this.b.f = false;
                return Unit.a;
            default:
                return new androidx.compose.ui.geometry.b(((androidx.compose.ui.geometry.b) this.b.getValue()).a);
        }
    }
}
