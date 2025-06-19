package androidx.compose.foundation.lazy.layout;

import androidx.appcompat.widget.C0122z;
import java.util.Comparator;

/* loaded from: classes.dex */
public final class J implements Comparator {
    public final /* synthetic */ int a;
    public final /* synthetic */ C0122z b;

    public /* synthetic */ J(C0122z c0122z, int i) {
        this.a = i;
        this.b = c0122z;
    }

    @Override // java.util.Comparator
    public final int compare(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                Object key = ((V) obj).getKey();
                C0122z c0122z = this.b;
                return kotlin.comparisons.a.b(Integer.valueOf(c0122z.a(key)), Integer.valueOf(c0122z.a(((V) obj2).getKey())));
            default:
                Object key2 = ((V) obj2).getKey();
                C0122z c0122z2 = this.b;
                return kotlin.comparisons.a.b(Integer.valueOf(c0122z2.a(key2)), Integer.valueOf(c0122z2.a(((V) obj).getKey())));
        }
    }
}
