package androidx.camera.camera2.internal;

import android.view.View;
import androidx.camera.core.impl.AbstractC0171j;
import com.braze.ui.contentcards.adapters.ContentCardAdapter;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3116c6;
import com.google.android.material.sidesheet.SideSheetBehavior;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.function.IntConsumer;

/* renamed from: androidx.camera.camera2.internal.j, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class RunnableC0133j implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ int b;
    public final /* synthetic */ Object c;

    public /* synthetic */ RunnableC0133j(Object obj, int i, int i2) {
        this.a = i2;
        this.c = obj;
        this.b = i;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                ((AbstractC0171j) this.c).a(this.b);
                return;
            case 1:
                LinkedHashSet linkedHashSet = (LinkedHashSet) this.c;
                int i = this.b;
                Iterator it2 = linkedHashSet.iterator();
                while (it2.hasNext()) {
                    k0 k0Var = (k0) it2.next();
                    if (i == 5) {
                        synchronized (k0Var.p) {
                            try {
                                if (k0Var.m() && k0Var.q != null) {
                                    k0.l();
                                    Iterator it3 = k0Var.q.iterator();
                                    while (it3.hasNext()) {
                                        ((androidx.camera.core.impl.J) it3.next()).a();
                                    }
                                }
                            } finally {
                            }
                        }
                    } else {
                        k0Var.getClass();
                    }
                }
                return;
            case 2:
                ((IntConsumer) this.c).accept(this.b);
                return;
            case 3:
                ((androidx.core.content.res.b) this.c).i(this.b);
                return;
            case 4:
                ((ContentCardAdapter) this.c).notifyItemChanged(this.b);
                return;
            case 5:
                SideSheetBehavior sideSheetBehavior = (SideSheetBehavior) this.c;
                View view = (View) sideSheetBehavior.p.get();
                if (view != null) {
                    sideSheetBehavior.z(view, this.b, false);
                    return;
                }
                return;
            default:
                com.quizlet.baseui.base.b bVar = (com.quizlet.baseui.base.b) this.c;
                if (bVar.isFinishing()) {
                    return;
                }
                AbstractC3116c6.h(this.b, bVar.getSupportFragmentManager());
                return;
        }
    }
}
