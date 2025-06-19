package com.google.android.gms.internal.play_billing;

import java.io.Serializable;

/* loaded from: classes2.dex */
public final class M extends N implements Serializable {
    public static final M b = new M(0);
    public static final M c = new M(1);
    public final /* synthetic */ int a;

    public /* synthetic */ M(int i) {
        this.a = i;
    }

    @Override // java.util.Comparator
    public final /* bridge */ /* synthetic */ int compare(Object obj, Object obj2) {
        switch (this.a) {
            case 0:
                Comparable comparable = (Comparable) obj;
                Comparable comparable2 = (Comparable) obj2;
                comparable.getClass();
                comparable2.getClass();
                return comparable.compareTo(comparable2);
            default:
                O o = (O) obj;
                O o2 = (O) obj2;
                return AbstractC3835t.a.b(o.a, o2.a).b(o.b, o2.b).a();
        }
    }

    public String toString() {
        switch (this.a) {
            case 0:
                return "Ordering.natural()";
            default:
                return super.toString();
        }
    }
}
