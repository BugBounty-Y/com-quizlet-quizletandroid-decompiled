package androidx.compose.animation;

import androidx.compose.animation.core.E0;
import androidx.compose.runtime.L0;
import kotlin.jvm.functions.Function0;

/* renamed from: androidx.compose.animation.x, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0296x extends kotlin.jvm.internal.r implements Function0 {
    public final /* synthetic */ int a;
    public final /* synthetic */ E0 b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0296x(E0 e0, int i) {
        super(0);
        this.a = i;
        this.b = e0;
    }

    @Override // kotlin.jvm.functions.Function0
    public final Object invoke() {
        switch (this.a) {
            case 0:
                E0 e0 = this.b;
                Object objT = e0.a.t();
                O o = O.c;
                return Boolean.valueOf(objT == o && ((L0) e0.d).getValue() == o);
            default:
                return Long.valueOf(this.b.b());
        }
    }
}
