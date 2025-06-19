package androidx.compose.ui.graphics.vector;

import androidx.compose.animation.d0;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class H extends J implements Iterable, kotlin.jvm.internal.markers.a {
    public final String a;
    public final float b;
    public final float c;
    public final float d;
    public final float e;
    public final float f;
    public final float g;
    public final float h;
    public final List i;
    public final ArrayList j;

    public H(String str, float f, float f2, float f3, float f4, float f5, float f6, float f7, List list, ArrayList arrayList) {
        this.a = str;
        this.b = f;
        this.c = f2;
        this.d = f3;
        this.e = f4;
        this.f = f5;
        this.g = f6;
        this.h = f7;
        this.i = list;
        this.j = arrayList;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || !(obj instanceof H)) {
            return false;
        }
        H h = (H) obj;
        return Intrinsics.b(this.a, h.a) && this.b == h.b && this.c == h.c && this.d == h.d && this.e == h.e && this.f == h.f && this.g == h.g && this.h == h.h && Intrinsics.b(this.i, h.i) && Intrinsics.b(this.j, h.j);
    }

    public final int hashCode() {
        return this.j.hashCode() + d0.f(android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(this.a.hashCode() * 31, this.b, 31), this.c, 31), this.d, 31), this.e, 31), this.f, 31), this.g, 31), this.h, 31), 31, this.i);
    }

    @Override // java.lang.Iterable
    public final Iterator iterator() {
        return new G(this);
    }
}
