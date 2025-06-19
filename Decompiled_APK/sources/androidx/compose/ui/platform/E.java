package androidx.compose.ui.platform;

import android.view.accessibility.AccessibilityEvent;
import androidx.compose.animation.core.C0242g;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes.dex */
public final class E extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ F b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ E(F f, int i) {
        super(1);
        this.a = i;
        this.b = f;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        switch (this.a) {
            case 0:
                F f = this.b;
                return Boolean.valueOf(f.d.getParent().requestSendAccessibilityEvent(f.d, (AccessibilityEvent) obj));
            default:
                N0 n0 = (N0) obj;
                F f2 = this.b;
                f2.getClass();
                if (n0.b.contains(n0)) {
                    f2.d.getSnapshotObserver().a(n0, f2.M, new C0242g(25, n0, f2));
                }
                return Unit.a;
        }
    }
}
