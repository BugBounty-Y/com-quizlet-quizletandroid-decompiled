package androidx.work.impl.utils;

import android.view.View;
import androidx.appcompat.widget.ActionMenuView;
import androidx.work.impl.C1433e;
import androidx.work.impl.F;
import androidx.work.z;
import com.google.android.gms.internal.ads.Ui;
import com.google.android.material.bottomappbar.BottomAppBar;
import java.util.Set;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class j implements Runnable {
    public final /* synthetic */ int a = 0;
    public final boolean b;
    public final int c;
    public final Object d;
    public final Object e;

    public /* synthetic */ j(Ui ui, View view, boolean z, int i) {
        this.d = ui;
        this.e = view;
        this.b = z;
        this.c = i;
    }

    /* JADX WARN: Type inference failed for: r1v12, types: [com.google.android.gms.internal.ads.uj, com.google.android.gms.internal.ads.x5] */
    /* JADX WARN: Type inference failed for: r1v13, types: [com.google.android.gms.internal.ads.uj, com.google.android.gms.internal.ads.x5] */
    /* JADX WARN: Type inference failed for: r1v14, types: [com.google.android.gms.internal.ads.uj, com.google.android.gms.internal.ads.x5] */
    @Override // java.lang.Runnable
    public final void run() {
        F fB;
        switch (this.a) {
            case 0:
                if (this.b) {
                    C1433e c1433e = (C1433e) this.d;
                    androidx.work.impl.j jVar = (androidx.work.impl.j) this.e;
                    int i = this.c;
                    c1433e.getClass();
                    String str = jVar.a.a;
                    synchronized (c1433e.k) {
                        fB = c1433e.b(str);
                    }
                    C1433e.d(fB, i);
                } else {
                    C1433e c1433e2 = (C1433e) this.d;
                    androidx.work.impl.j jVar2 = (androidx.work.impl.j) this.e;
                    int i2 = this.c;
                    c1433e2.getClass();
                    String str2 = jVar2.a.a;
                    synchronized (c1433e2.k) {
                        try {
                            if (c1433e2.f.get(str2) != null) {
                                z.c().getClass();
                            } else {
                                Set set = (Set) c1433e2.h.get(str2);
                                if (set != null && set.contains(jVar2)) {
                                    C1433e.d(c1433e2.b(str2), i2);
                                }
                            }
                        } finally {
                        }
                    }
                }
                z zVarC = z.c();
                z.e("StopWorkRunnable");
                String str3 = ((androidx.work.impl.j) this.e).a.a;
                zVarC.getClass();
                return;
            case 1:
                Ui ui = (Ui) this.d;
                ?? r1 = ui.u;
                if (r1 == 0) {
                    com.google.android.gms.ads.internal.util.client.i.d("Ad should be associated with an ad view before calling performClickForCustomGesture()");
                    return;
                }
                ui.l.j((View) this.e, r1.f(), ui.u.k(), ui.u.l(), this.b, ui.j(), this.c);
                return;
            default:
                int i3 = this.c;
                boolean z = this.b;
                BottomAppBar bottomAppBar = (BottomAppBar) this.e;
                ((ActionMenuView) this.d).setTranslationX(bottomAppBar.D(r3, i3, z));
                return;
        }
    }

    public j(C1433e processor, androidx.work.impl.j token, boolean z, int i) {
        Intrinsics.checkNotNullParameter(processor, "processor");
        Intrinsics.checkNotNullParameter(token, "token");
        this.d = processor;
        this.e = token;
        this.b = z;
        this.c = i;
    }

    public j(BottomAppBar bottomAppBar, ActionMenuView actionMenuView, int i, boolean z) {
        this.e = bottomAppBar;
        this.d = actionMenuView;
        this.c = i;
        this.b = z;
    }
}
