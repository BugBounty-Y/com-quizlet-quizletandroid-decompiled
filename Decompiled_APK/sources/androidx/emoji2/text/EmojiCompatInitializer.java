package androidx.emoji2.text;

import android.content.Context;
import androidx.lifecycle.C;
import androidx.lifecycle.J;
import androidx.lifecycle.ProcessLifecycleInitializer;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;

/* loaded from: classes.dex */
public class EmojiCompatInitializer implements androidx.startup.b {
    @Override // androidx.startup.b
    public final Object create(Context context) {
        Object objB;
        u uVar = new u(new m(context, 0));
        uVar.a = 1;
        if (j.k == null) {
            synchronized (j.j) {
                try {
                    if (j.k == null) {
                        j.k = new j(uVar);
                    }
                } finally {
                }
            }
        }
        androidx.startup.a aVarC = androidx.startup.a.c(context);
        aVarC.getClass();
        synchronized (androidx.startup.a.e) {
            try {
                objB = aVarC.a.get(ProcessLifecycleInitializer.class);
                if (objB == null) {
                    objB = aVarC.b(ProcessLifecycleInitializer.class, new HashSet());
                }
            } finally {
            }
        }
        C lifecycle = ((J) objB).getLifecycle();
        lifecycle.a(new k(this, lifecycle));
        return Boolean.TRUE;
    }

    @Override // androidx.startup.b
    public final List dependencies() {
        return Collections.singletonList(ProcessLifecycleInitializer.class);
    }
}
