package androidx.glance.appwidget;

import android.os.Trace;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class M0 {
    public static final M0 a = new M0();

    public final void a(@NotNull String str, int i) {
        Trace.beginAsyncSection(str, i);
    }

    public final void b(@NotNull String str, int i) {
        Trace.endAsyncSection(str, i);
    }
}
