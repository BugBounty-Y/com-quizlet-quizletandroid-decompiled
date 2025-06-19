package androidx.compose.material3.windowsizeclass;

import com.google.android.gms.internal.mlkit_vision_barcode.B4;
import java.util.List;
import java.util.Set;
import kotlin.collections.B;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class c implements Comparable {
    public static final Set b;
    public static final List c;
    public final int a;

    static {
        int i = 0;
        int i2 = 1;
        int i3 = 2;
        c[] elements = {new c(i), new c(i2), new c(i3)};
        Intrinsics.checkNotNullParameter(elements, "elements");
        b = C4933y.T(elements);
        List listJ = B.j(new c(i3), new c(i2), new c(i));
        c = listJ;
        CollectionsKt.A0(listJ);
    }

    public /* synthetic */ c(int i) {
        this.a = i;
    }

    @Override // java.lang.Comparable
    public final int compareTo(Object obj) {
        return Float.compare(B4.a(this.a), B4.a(((c) obj).a));
    }

    public final boolean equals(Object obj) {
        if (obj instanceof c) {
            return this.a == ((c) obj).a;
        }
        return false;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        int i = this.a;
        return "WindowWidthSizeClass.".concat(i == 0 ? "Compact" : i == 1 ? "Medium" : i == 2 ? "Expanded" : "");
    }
}
