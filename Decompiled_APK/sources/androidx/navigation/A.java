package androidx.navigation;

import android.os.Bundle;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class A implements Comparable {
    public final B a;
    public final Bundle b;
    public final boolean c;
    public final int d;
    public final boolean e;

    public A(B destination, Bundle bundle, boolean z, int i, boolean z2) {
        Intrinsics.checkNotNullParameter(destination, "destination");
        this.a = destination;
        this.b = bundle;
        this.c = z;
        this.d = i;
        this.e = z2;
    }

    @Override // java.lang.Comparable
    /* renamed from: a, reason: merged with bridge method [inline-methods] */
    public final int compareTo(A other) {
        Intrinsics.checkNotNullParameter(other, "other");
        boolean z = this.c;
        if (z && !other.c) {
            return 1;
        }
        if (!z && other.c) {
            return -1;
        }
        int i = this.d - other.d;
        if (i > 0) {
            return 1;
        }
        if (i < 0) {
            return -1;
        }
        Bundle source = other.b;
        Bundle source2 = this.b;
        if (source2 != null && source == null) {
            return 1;
        }
        if (source2 == null && source != null) {
            return -1;
        }
        if (source2 != null) {
            Intrinsics.checkNotNullParameter(source2, "source");
            int size = source2.size();
            Intrinsics.d(source);
            Intrinsics.checkNotNullParameter(source, "source");
            int size2 = size - source.size();
            if (size2 > 0) {
                return 1;
            }
            if (size2 < 0) {
                return -1;
            }
        }
        boolean z2 = other.e;
        boolean z3 = this.e;
        if (!z3 || z2) {
            return (z3 || !z2) ? 0 : -1;
        }
        return 1;
    }
}
