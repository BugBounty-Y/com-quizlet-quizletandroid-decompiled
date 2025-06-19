package androidx.fragment.app;

import android.os.Handler;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class O extends L {
    public final I a;
    public final I b;
    public final Handler c;
    public final C1138i0 d;

    public O(I context) {
        Intrinsics.checkNotNullParameter(context, "activity");
        Handler handler = new Handler();
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(handler, "handler");
        this.a = context;
        this.b = context;
        this.c = handler;
        this.d = new C1138i0();
    }
}
