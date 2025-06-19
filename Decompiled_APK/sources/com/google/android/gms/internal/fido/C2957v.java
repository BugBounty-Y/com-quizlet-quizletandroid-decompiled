package com.google.android.gms.internal.fido;

import java.io.Serializable;

/* renamed from: com.google.android.gms.internal.fido.v, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2957v extends AbstractC2958w implements Serializable {
    public static final C2957v b = new C2957v(0);
    public static final C2957v c = new C2957v(1);
    public final /* synthetic */ int a;

    public /* synthetic */ C2957v(int i) {
        this.a = i;
    }

    @Override // com.google.android.gms.internal.fido.AbstractC2958w
    public final AbstractC2958w a() {
        switch (this.a) {
            case 0:
                return c;
            default:
                return b;
        }
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
                Comparable comparable3 = (Comparable) obj;
                Comparable comparable4 = (Comparable) obj2;
                comparable3.getClass();
                if (comparable3 == comparable4) {
                    return 0;
                }
                return comparable4.compareTo(comparable3);
        }
    }

    public final String toString() {
        switch (this.a) {
            case 0:
                return "Ordering.natural()";
            default:
                return "Ordering.natural().reverse()";
        }
    }
}
