package androidx.compose.ui.viewinterop;

import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class g extends r implements Function0 {
    public static final g b = new g(0, 0);
    public static final g c = new g(0, 1);
    public static final g d = new g(0, 2);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ g(int i, int i2) {
        super(i);
        this.a = i2;
    }

    @Override // kotlin.jvm.functions.Function0
    public final /* bridge */ /* synthetic */ Object invoke() {
        switch (this.a) {
        }
        return Unit.a;
    }
}
