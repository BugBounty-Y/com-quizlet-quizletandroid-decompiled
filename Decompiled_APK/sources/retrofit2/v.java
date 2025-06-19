package retrofit2;

import java.lang.reflect.Array;
import java.util.Iterator;

/* loaded from: classes3.dex */
public final class v extends S {
    public final /* synthetic */ int d;
    public final /* synthetic */ S e;

    public /* synthetic */ v(S s, int i) {
        this.d = i;
        this.e = s;
    }

    @Override // retrofit2.S
    public final void a(H h, Object obj) {
        switch (this.d) {
            case 0:
                Iterable iterable = (Iterable) obj;
                if (iterable != null) {
                    Iterator it2 = iterable.iterator();
                    while (it2.hasNext()) {
                        this.e.a(h, it2.next());
                    }
                    break;
                }
                break;
            default:
                if (obj != null) {
                    int length = Array.getLength(obj);
                    for (int i = 0; i < length; i++) {
                        this.e.a(h, Array.get(obj, i));
                    }
                    break;
                }
                break;
        }
    }
}
