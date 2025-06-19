package androidx.compose.foundation.layout;

/* renamed from: androidx.compose.foundation.layout.m0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0399m0 implements H0, InterfaceC0397l0 {
    public static final C0399m0 a = new C0399m0();

    @Override // androidx.compose.foundation.layout.H0
    public final androidx.compose.ui.q a(androidx.compose.ui.q qVar, float f, boolean z) {
        if (f <= 0.0d) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", f, "; must be greater than zero").toString());
        }
        if (f > Float.MAX_VALUE) {
            f = Float.MAX_VALUE;
        }
        return qVar.g(new LayoutWeightElement(f, true));
    }
}
