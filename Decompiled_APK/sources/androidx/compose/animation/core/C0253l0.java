package androidx.compose.animation.core;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.animation.core.l0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0253l0 implements D {
    public final float a;
    public final float b;
    public final Object c;

    public C0253l0(float f, float f2, Object obj) {
        this.a = f;
        this.b = f2;
        this.c = obj;
    }

    @Override // androidx.compose.animation.core.InterfaceC0256n
    public final N0 a(L0 l0) {
        Object obj = this.c;
        return new com.google.android.gms.internal.instantapps.a(this.a, this.b, obj == null ? null : (AbstractC0267t) l0.a.invoke(obj));
    }

    public final boolean equals(Object obj) {
        if (obj instanceof C0253l0) {
            C0253l0 c0253l0 = (C0253l0) obj;
            if (c0253l0.a == this.a && c0253l0.b == this.b && Intrinsics.b(c0253l0.c, this.c)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        Object obj = this.c;
        return Float.hashCode(this.b) + android.support.v4.media.session.a.b((obj != null ? obj.hashCode() : 0) * 31, this.a, 31);
    }

    public /* synthetic */ C0253l0(Object obj, int i) {
        this(1.0f, 1500.0f, (i & 4) != 0 ? null : obj);
    }
}
