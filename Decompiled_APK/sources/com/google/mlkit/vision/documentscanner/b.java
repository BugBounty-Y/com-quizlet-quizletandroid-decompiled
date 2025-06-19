package com.google.mlkit.vision.documentscanner;

import com.google.android.gms.common.internal.u;
import java.util.Arrays;

/* loaded from: classes2.dex */
public final class b {
    public final int a;
    public final int[] b;
    public final boolean c;
    public final boolean d;
    public final boolean e;
    public final boolean f;

    static {
        new b(new a());
    }

    public /* synthetic */ b(a aVar) {
        aVar.getClass();
        this.a = aVar.a;
        this.b = aVar.b;
        this.c = aVar.c;
        this.d = aVar.d;
        this.e = aVar.e;
        this.f = aVar.f;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        bVar.getClass();
        return u.l(null, null) && this.a == bVar.a && Arrays.equals(this.b, bVar.b) && u.l(null, null) && this.c == bVar.c && this.d == bVar.d && this.e == bVar.e && this.f == bVar.f;
    }

    public final int hashCode() {
        Boolean bool = Boolean.TRUE;
        return Arrays.hashCode(new Object[]{null, 1, bool, bool, Integer.valueOf(this.a), Integer.valueOf(Arrays.hashCode(this.b)), null, Boolean.valueOf(this.c), Boolean.valueOf(this.d), Boolean.valueOf(this.e), Boolean.valueOf(this.f)});
    }
}
