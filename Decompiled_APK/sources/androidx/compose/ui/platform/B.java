package androidx.compose.ui.platform;

import java.util.Comparator;
import kotlin.Pair;

/* loaded from: classes.dex */
public final class B implements Comparator {
    public static final B b = new B(0);
    public static final B c = new B(1);
    public static final B d = new B(2);
    public final /* synthetic */ int a;

    public /* synthetic */ B(int i) {
        this.a = i;
    }

    @Override // java.util.Comparator
    public final int compare(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                androidx.compose.ui.geometry.c cVarF = ((androidx.compose.ui.semantics.o) obj).f();
                androidx.compose.ui.geometry.c cVarF2 = ((androidx.compose.ui.semantics.o) obj2).f();
                int iCompare = Float.compare(cVarF.a, cVarF2.a);
                if (iCompare != 0) {
                    return iCompare;
                }
                int iCompare2 = Float.compare(cVarF.b, cVarF2.b);
                if (iCompare2 != 0) {
                    return iCompare2;
                }
                int iCompare3 = Float.compare(cVarF.d, cVarF2.d);
                return iCompare3 != 0 ? iCompare3 : Float.compare(cVarF.c, cVarF2.c);
            case 1:
                androidx.compose.ui.geometry.c cVarF3 = ((androidx.compose.ui.semantics.o) obj).f();
                androidx.compose.ui.geometry.c cVarF4 = ((androidx.compose.ui.semantics.o) obj2).f();
                int iCompare4 = Float.compare(cVarF4.c, cVarF3.c);
                if (iCompare4 != 0) {
                    return iCompare4;
                }
                int iCompare5 = Float.compare(cVarF3.b, cVarF4.b);
                if (iCompare5 != 0) {
                    return iCompare5;
                }
                int iCompare6 = Float.compare(cVarF3.d, cVarF4.d);
                return iCompare6 != 0 ? iCompare6 : Float.compare(cVarF4.a, cVarF3.a);
            default:
                Pair pair = (Pair) obj;
                Pair pair2 = (Pair) obj2;
                int iCompare7 = Float.compare(((androidx.compose.ui.geometry.c) pair.a).b, ((androidx.compose.ui.geometry.c) pair2.a).b);
                return iCompare7 != 0 ? iCompare7 : Float.compare(((androidx.compose.ui.geometry.c) pair.a).d, ((androidx.compose.ui.geometry.c) pair2.a).d);
        }
    }
}
