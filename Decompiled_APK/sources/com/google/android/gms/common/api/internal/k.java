package com.google.android.gms.common.api.internal;

import android.view.View;
import androidx.core.view.V;
import com.google.android.gms.common.Feature;
import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.google.android.material.sidesheet.SideSheetBehavior;
import com.quizlet.db.data.models.persisted.base.ModelType;
import com.quizlet.db.data.net.tasks.ExecutionRouter;
import java.lang.ref.WeakReference;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public final class k {
    public final /* synthetic */ int a;
    public int b;
    public boolean c;
    public Object d;
    public Object e;

    public /* synthetic */ k() {
        this.a = 0;
    }

    public y a() {
        com.google.android.gms.common.internal.u.a("execute parameter required", ((i) this.d) != null);
        return new y(this, (Feature[]) this.e, this.c, this.b);
    }

    public void b(int i) {
        switch (this.a) {
            case 1:
                BottomSheetBehavior bottomSheetBehavior = (BottomSheetBehavior) this.e;
                WeakReference weakReference = bottomSheetBehavior.e1;
                if (weakReference != null && weakReference.get() != null) {
                    this.b = i;
                    if (!this.c) {
                        View view = (View) bottomSheetBehavior.e1.get();
                        w wVar = (w) this.d;
                        WeakHashMap weakHashMap = V.a;
                        view.postOnAnimation(wVar);
                        this.c = true;
                        break;
                    }
                }
                break;
            default:
                SideSheetBehavior sideSheetBehavior = (SideSheetBehavior) this.e;
                WeakReference weakReference2 = sideSheetBehavior.p;
                if (weakReference2 != null && weakReference2.get() != null) {
                    this.b = i;
                    if (!this.c) {
                        View view2 = (View) sideSheetBehavior.p.get();
                        androidx.compose.ui.text.input.C c = (androidx.compose.ui.text.input.C) this.d;
                        WeakHashMap weakHashMap2 = V.a;
                        view2.postOnAnimation(c);
                        this.c = true;
                        break;
                    }
                }
                break;
        }
    }

    public k(ModelType modelType, int i, androidx.compose.ui.node.V v, com.google.android.datatransport.cct.internal.s sVar, ExecutionRouter executionRouter) {
        this.a = 3;
        this.b = i;
        this.d = v;
        this.e = executionRouter;
        this.c = modelType.hasMultipleFieldIdentity();
    }

    public k(SideSheetBehavior sideSheetBehavior) {
        this.a = 2;
        this.e = sideSheetBehavior;
        this.d = new androidx.compose.ui.text.input.C(this, 24);
    }

    public k(BottomSheetBehavior bottomSheetBehavior) {
        this.a = 1;
        this.e = bottomSheetBehavior;
        this.d = new w(this, 12);
    }
}
