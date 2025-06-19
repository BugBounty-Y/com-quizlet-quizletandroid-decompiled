package androidx.compose.foundation.lazy.layout;

import androidx.compose.animation.core.C0238e;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* renamed from: androidx.compose.foundation.lazy.layout.w, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0450w extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ androidx.compose.ui.graphics.layer.b b;
    public final /* synthetic */ E c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0450w(androidx.compose.ui.graphics.layer.b bVar, E e, int i) {
        super(1);
        this.a = i;
        this.b = bVar;
        this.c = e;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) throws Throwable {
        switch (this.a) {
            case 0:
                this.b.f(((Number) ((C0238e) obj).d()).floatValue());
                this.c.c.invoke();
                break;
            default:
                this.b.f(((Number) ((C0238e) obj).d()).floatValue());
                this.c.c.invoke();
                break;
        }
        return Unit.a;
    }
}
