package androidx.compose.foundation.lazy.layout;

import java.util.Comparator;

/* loaded from: classes.dex */
public final class I implements Comparator {
    public final /* synthetic */ int a;
    public final /* synthetic */ P b;

    public /* synthetic */ I(P p, int i) {
        this.a = i;
        this.b = p;
    }

    @Override // java.util.Comparator
    public final int compare(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                Object key = ((V) obj).getKey();
                P p = this.b;
                return kotlin.comparisons.a.b(Integer.valueOf(p.a(key)), Integer.valueOf(p.a(((V) obj2).getKey())));
            default:
                Object key2 = ((V) obj2).getKey();
                P p2 = this.b;
                return kotlin.comparisons.a.b(Integer.valueOf(p2.a(key2)), Integer.valueOf(p2.a(((V) obj).getKey())));
        }
    }
}
