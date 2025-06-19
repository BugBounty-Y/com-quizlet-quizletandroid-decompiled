package androidx.compose.ui.graphics.vector;

import androidx.compose.animation.d0;
import androidx.compose.ui.graphics.C0861v;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.graphics.vector.f, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0867f {
    public static final com.quizlet.shared.usecase.srs.a k = new com.quizlet.shared.usecase.srs.a(2);
    public static int l;
    public final String a;
    public final float b;
    public final float c;
    public final float d;
    public final float e;
    public final H f;
    public final long g;
    public final int h;
    public final boolean i;
    public final int j;

    public C0867f(String str, float f, float f2, float f3, float f4, H h, long j, int i, boolean z) {
        int i2;
        synchronized (k) {
            i2 = l;
            l = i2 + 1;
        }
        this.a = str;
        this.b = f;
        this.c = f2;
        this.d = f3;
        this.e = f4;
        this.f = h;
        this.g = j;
        this.h = i;
        this.i = z;
        this.j = i2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0867f)) {
            return false;
        }
        C0867f c0867f = (C0867f) obj;
        return Intrinsics.b(this.a, c0867f.a) && androidx.compose.ui.unit.e.a(this.b, c0867f.b) && androidx.compose.ui.unit.e.a(this.c, c0867f.c) && this.d == c0867f.d && this.e == c0867f.e && this.f.equals(c0867f.f) && C0861v.c(this.g, c0867f.g) && this.h == c0867f.h && this.i == c0867f.i;
    }

    public final int hashCode() {
        int iHashCode = (this.f.hashCode() + android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(this.a.hashCode() * 31, this.b, 31), this.c, 31), this.d, 31), this.e, 31)) * 31;
        int i = C0861v.h;
        kotlin.C c = kotlin.D.b;
        return Boolean.hashCode(this.i) + d0.b(this.h, d0.d(iHashCode, 31, this.g), 31);
    }
}
