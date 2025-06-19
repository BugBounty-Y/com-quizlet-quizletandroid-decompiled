package androidx.compose.foundation.gestures;

import kotlin.Unit;

/* renamed from: androidx.compose.foundation.gestures.n, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0339n implements Z {
    public final T a;
    public final C0337m b = new C0337m(this, 0);
    public final androidx.compose.foundation.y0 c = new androidx.compose.foundation.y0();

    public C0339n(T t) {
        this.a = t;
    }

    @Override // androidx.compose.foundation.gestures.Z
    public final Object a(V v, P p) {
        Object objM = kotlinx.coroutines.E.m(new C0335l(this, v, null), p);
        return objM == kotlin.coroutines.intrinsics.a.a ? objM : Unit.a;
    }
}
