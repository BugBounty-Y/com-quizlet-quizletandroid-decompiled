package kotlin.jvm.internal;

import androidx.compose.animation.d0;
import java.io.Serializable;

/* renamed from: kotlin.jvm.internal.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public class C4942a implements InterfaceC4954m, Serializable {
    public final Object a;
    public final Class b;
    public final String c;
    public final String d;
    public final boolean e = false;
    public final int f;
    public final int g;

    public C4942a(int i, int i2, Class cls, Object obj, String str, String str2) {
        this.a = obj;
        this.b = cls;
        this.c = str;
        this.d = str2;
        this.f = i;
        this.g = i2 >> 1;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4942a)) {
            return false;
        }
        C4942a c4942a = (C4942a) obj;
        return this.e == c4942a.e && this.f == c4942a.f && this.g == c4942a.g && Intrinsics.b(this.a, c4942a.a) && this.b.equals(c4942a.b) && this.c.equals(c4942a.c) && this.d.equals(c4942a.d);
    }

    @Override // kotlin.jvm.internal.InterfaceC4954m
    public final int getArity() {
        return this.f;
    }

    public final int hashCode() {
        Object obj = this.a;
        return ((((d0.e(d0.e((this.b.hashCode() + ((obj != null ? obj.hashCode() : 0) * 31)) * 31, 31, this.c), 31, this.d) + (this.e ? 1231 : 1237)) * 31) + this.f) * 31) + this.g;
    }

    public final String toString() {
        K.a.getClass();
        return L.a(this);
    }
}
