package androidx.camera.camera2.internal;

import android.view.View;
import androidx.activity.RunnableC0041m;
import com.google.android.material.behavior.SwipeDismissBehavior;
import java.util.WeakHashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class A implements Runnable {
    public final /* synthetic */ int a;
    public boolean b;
    public final Object c;
    public final Object d;

    public A(androidx.lifecycle.L registry, androidx.lifecycle.A event) {
        this.a = 1;
        Intrinsics.checkNotNullParameter(registry, "registry");
        Intrinsics.checkNotNullParameter(event, "event");
        this.c = registry;
        this.d = event;
    }

    @Override // java.lang.Runnable
    public final void run() {
        com.airbnb.lottie.network.d dVar;
        Object obj = this.d;
        Object obj2 = this.c;
        switch (this.a) {
            case 0:
                ((androidx.camera.core.impl.utils.executor.k) obj2).execute(new RunnableC0041m(this, 4));
                break;
            case 1:
                if (!this.b) {
                    ((androidx.lifecycle.L) obj2).e((androidx.lifecycle.A) obj);
                    this.b = true;
                    break;
                }
                break;
            default:
                SwipeDismissBehavior swipeDismissBehavior = (SwipeDismissBehavior) obj;
                androidx.customview.widget.d dVar2 = swipeDismissBehavior.a;
                View view = (View) obj2;
                if (dVar2 != null && dVar2.f()) {
                    WeakHashMap weakHashMap = androidx.core.view.V.a;
                    view.postOnAnimation(this);
                    break;
                } else if (this.b && (dVar = swipeDismissBehavior.b) != null) {
                    dVar.m(view);
                    break;
                }
                break;
        }
    }

    public A(SwipeDismissBehavior swipeDismissBehavior, View view, boolean z) {
        this.a = 2;
        this.d = swipeDismissBehavior;
        this.c = view;
        this.b = z;
    }

    public A(B b, androidx.camera.core.impl.utils.executor.k kVar) {
        this.a = 0;
        this.d = b;
        this.b = false;
        this.c = kVar;
    }
}
