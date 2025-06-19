package androidx.fragment.app;

import android.view.ViewGroup;
import androidx.activity.C0030b;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class G0 {
    public boolean a;
    public boolean b;

    public boolean a() {
        return this instanceof C1133g;
    }

    public abstract void b(ViewGroup viewGroup);

    public abstract void c(ViewGroup viewGroup);

    public void d(C0030b backEvent, ViewGroup container) {
        Intrinsics.checkNotNullParameter(backEvent, "backEvent");
        Intrinsics.checkNotNullParameter(container, "container");
    }

    public void e(ViewGroup container) {
        Intrinsics.checkNotNullParameter(container, "container");
    }
}
