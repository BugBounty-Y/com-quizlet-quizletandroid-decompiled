package androidx.compose.ui.viewinterop;

import androidx.compose.ui.node.E;
import androidx.compose.ui.q;
import androidx.lifecycle.J;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.r;

/* loaded from: classes.dex */
public final class l extends r implements Function2 {
    public static final l b = new l(2, 0);
    public static final l c = new l(2, 1);
    public static final l d = new l(2, 2);
    public static final l e = new l(2, 3);
    public static final l f = new l(2, 4);
    public static final l g = new l(2, 5);
    public static final l h = new l(2, 6);
    public static final l i = new l(2, 7);
    public static final l j = new l(2, 8);
    public static final l k = new l(2, 9);
    public final /* synthetic */ int a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ l(int i2, int i3) {
        super(i2);
        this.a = i3;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        int i2;
        switch (this.a) {
            case 0:
                k.i((E) obj).setResetBlock((Function1) obj2);
                return Unit.a;
            case 1:
                k.i((E) obj).setUpdateBlock((Function1) obj2);
                return Unit.a;
            case 2:
                k.i((E) obj).setReleaseBlock((Function1) obj2);
                return Unit.a;
            case 3:
                k.i((E) obj).setUpdateBlock((Function1) obj2);
                return Unit.a;
            case 4:
                k.i((E) obj).setReleaseBlock((Function1) obj2);
                return Unit.a;
            case 5:
                k.i((E) obj).setModifier((q) obj2);
                return Unit.a;
            case 6:
                k.i((E) obj).setDensity((androidx.compose.ui.unit.b) obj2);
                return Unit.a;
            case 7:
                k.i((E) obj).setLifecycleOwner((J) obj2);
                return Unit.a;
            case 8:
                k.i((E) obj).setSavedStateRegistryOwner((androidx.savedstate.f) obj2);
                return Unit.a;
            default:
                p pVarI = k.i((E) obj);
                int iOrdinal = ((androidx.compose.ui.unit.k) obj2).ordinal();
                if (iOrdinal != 0) {
                    i2 = 1;
                    if (iOrdinal != 1) {
                        throw new NoWhenBranchMatchedException();
                    }
                } else {
                    i2 = 0;
                }
                pVarI.setLayoutDirection(i2);
                return Unit.a;
        }
    }
}
