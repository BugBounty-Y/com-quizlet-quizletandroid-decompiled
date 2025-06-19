package androidx.fragment.app;

import android.view.View;
import androidx.transition.C1409l;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class s0 {
    public static final x0 a = new x0();
    public static final z0 b;

    static {
        z0 z0Var = null;
        try {
            z0Var = (z0) C1409l.class.getDeclaredConstructor(null).newInstance(null);
        } catch (Exception unused) {
        }
        b = z0Var;
    }

    public static final void a(int i, ArrayList views) {
        Intrinsics.checkNotNullParameter(views, "views");
        Iterator it2 = views.iterator();
        while (it2.hasNext()) {
            ((View) it2.next()).setVisibility(i);
        }
    }
}
