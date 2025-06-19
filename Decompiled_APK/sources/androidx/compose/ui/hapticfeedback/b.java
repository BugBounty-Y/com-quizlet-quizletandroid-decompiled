package androidx.compose.ui.hapticfeedback;

import androidx.compose.ui.platform.C0971v;

/* loaded from: classes.dex */
public final class b implements a {
    public final C0971v a;

    public b(C0971v c0971v) {
        this.a = c0971v;
    }

    public final void a() {
        this.a.performHapticFeedback(9);
    }
}
