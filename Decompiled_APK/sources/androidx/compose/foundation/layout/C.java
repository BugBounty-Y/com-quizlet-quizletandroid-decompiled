package androidx.compose.foundation.layout;

/* loaded from: classes.dex */
public interface C {
    static androidx.compose.ui.q a(androidx.compose.ui.q qVar, float f) {
        if (f <= 0.0d) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.i("invalid weight ", f, "; must be greater than zero").toString());
        }
        if (f > Float.MAX_VALUE) {
            f = Float.MAX_VALUE;
        }
        return qVar.g(new LayoutWeightElement(f, true));
    }
}
