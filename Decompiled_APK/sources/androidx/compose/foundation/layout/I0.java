package androidx.compose.foundation.layout;

/* loaded from: classes.dex */
public final class I0 implements H0 {
    public static final I0 a = new I0();

    @Override // androidx.compose.foundation.layout.H0
    public final androidx.compose.ui.q a(androidx.compose.ui.q qVar, float f, boolean z) {
        if (f <= 0.0d) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", f, "; must be greater than zero").toString());
        }
        if (f > Float.MAX_VALUE) {
            f = Float.MAX_VALUE;
        }
        return qVar.g(new LayoutWeightElement(f, z));
    }

    public final androidx.compose.ui.q b(androidx.compose.ui.q qVar, androidx.compose.ui.h hVar) {
        return qVar.g(new VerticalAlignElement(hVar));
    }
}
