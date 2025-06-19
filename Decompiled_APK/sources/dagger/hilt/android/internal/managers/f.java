package dagger.hilt.android.internal.managers;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.content.ContextWrapper;
import android.view.ViewGroup;
import androidx.fragment.app.Fragment;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.android.gms.internal.mlkit_vision_barcode.N6;
import com.google.android.gms.internal.mlkit_vision_barcode.R6;
import com.quizlet.quizletandroid.C4622e;
import com.quizlet.quizletandroid.u;
import com.quizlet.quizletandroid.v;

/* loaded from: classes3.dex */
public final class f implements dagger.hilt.internal.b {
    public final /* synthetic */ int a = 2;
    public final Object b = new Object();
    public volatile dagger.hilt.internal.a c;
    public final Object d;

    public f(com.lyft.android.scissors.b bVar) {
        this.d = bVar;
    }

    public static final Context b(Context context) {
        while ((context instanceof ContextWrapper) && !(context instanceof Activity)) {
            context = ((ContextWrapper) context).getBaseContext();
        }
        return context;
    }

    public com.quizlet.quizletandroid.j a() {
        Fragment fragment = (Fragment) this.d;
        if (fragment.getHost() == null) {
            throw new NullPointerException("Hilt Fragments must be attached before creating the component.");
        }
        R6.b(fragment.getHost() instanceof dagger.hilt.internal.b, "Hilt Fragments must be attached to an @AndroidEntryPoint Activity. Found: %s", fragment.getHost().getClass());
        C4622e c4622e = (C4622e) ((g) K6.b(g.class, fragment.getHost()));
        return new com.quizlet.quizletandroid.j(c4622e.b, c4622e.c, c4622e.d, fragment);
    }

    public dagger.hilt.internal.b c(boolean z) {
        ViewGroup viewGroup = (ViewGroup) this.d;
        Context context = viewGroup.getContext();
        while ((context instanceof ContextWrapper) && !dagger.hilt.internal.b.class.isInstance(context)) {
            context = ((ContextWrapper) context).getBaseContext();
        }
        Application applicationB = N6.b(context.getApplicationContext());
        Object obj = context;
        if (context == applicationB) {
            R6.b(z, "%s, Hilt view cannot be created using the application context. Use a Hilt Fragment or Activity context.", viewGroup.getClass());
            obj = null;
        }
        if (obj instanceof dagger.hilt.internal.b) {
            return (dagger.hilt.internal.b) obj;
        }
        if (z) {
            return null;
        }
        throw new IllegalStateException(viewGroup.getClass() + ", Hilt view must be attached to an @AndroidEntryPoint Fragment or Activity.");
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        switch (this.a) {
            case 0:
                if (((u) this.c) == null) {
                    synchronized (this.b) {
                        try {
                            if (((u) this.c) == null) {
                                this.c = ((com.lyft.android.scissors.b) this.d).c();
                            }
                        } finally {
                        }
                    }
                }
                return (u) this.c;
            case 1:
                if (((com.quizlet.quizletandroid.j) this.c) == null) {
                    synchronized (this.b) {
                        try {
                            if (((com.quizlet.quizletandroid.j) this.c) == null) {
                                this.c = a();
                            }
                        } finally {
                        }
                    }
                }
                return (com.quizlet.quizletandroid.j) this.c;
            default:
                if (((v) this.c) == null) {
                    synchronized (this.b) {
                        if (((v) this.c) == null) {
                            C4622e c4622e = (C4622e) ((k) K6.b(k.class, c(false)));
                            C4622e c4622e2 = c4622e.d;
                            this.c = new v(c4622e.b);
                        }
                    }
                }
                return (v) this.c;
        }
    }

    public f(Fragment fragment) {
        this.d = fragment;
    }

    public f(ViewGroup viewGroup) {
        this.d = viewGroup;
    }
}
