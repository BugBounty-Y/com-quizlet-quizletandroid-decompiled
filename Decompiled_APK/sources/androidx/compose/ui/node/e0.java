package androidx.compose.ui.node;

import java.util.Comparator;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class e0 implements Comparator {
    public static final e0 b = new e0(0);
    public final /* synthetic */ int a;

    public /* synthetic */ e0(int i) {
        this.a = i;
    }

    @Override // java.util.Comparator
    public final int compare(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                E e = (E) obj;
                E e2 = (E) obj2;
                int iG = Intrinsics.g(e2.k, e.k);
                return iG != 0 ? iG : Intrinsics.g(e.hashCode(), e2.hashCode());
            default:
                E e3 = (E) obj;
                E e4 = (E) obj2;
                int iG2 = Intrinsics.g(e3.k, e4.k);
                return iG2 != 0 ? iG2 : Intrinsics.g(e3.hashCode(), e4.hashCode());
        }
    }
}
