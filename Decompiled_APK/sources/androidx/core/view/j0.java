package androidx.core.view;

import android.os.Build;
import android.view.WindowInsets;
import android.view.WindowInsetsAnimation;
import android.view.WindowInsetsAnimation$Callback;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

/* loaded from: classes.dex */
public final class j0 extends WindowInsetsAnimation$Callback {
    public final AbstractC1047f0 a;
    public List b;
    public ArrayList c;
    public final HashMap d;

    public j0(AbstractC1047f0 abstractC1047f0) {
        super(abstractC1047f0.a);
        this.d = new HashMap();
        this.a = abstractC1047f0;
    }

    public final m0 a(WindowInsetsAnimation windowInsetsAnimation) {
        m0 m0Var = (m0) this.d.get(windowInsetsAnimation);
        if (m0Var == null) {
            m0Var = new m0(0, null, 0L);
            if (Build.VERSION.SDK_INT >= 30) {
                m0Var.a = new k0(windowInsetsAnimation);
            }
            this.d.put(windowInsetsAnimation, m0Var);
        }
        return m0Var;
    }

    public final void onEnd(WindowInsetsAnimation windowInsetsAnimation) {
        this.a.d(a(windowInsetsAnimation));
        this.d.remove(windowInsetsAnimation);
    }

    public final void onPrepare(WindowInsetsAnimation windowInsetsAnimation) {
        AbstractC1047f0 abstractC1047f0 = this.a;
        a(windowInsetsAnimation);
        abstractC1047f0.e();
    }

    public final WindowInsets onProgress(WindowInsets windowInsets, List list) {
        ArrayList arrayList = this.c;
        if (arrayList == null) {
            ArrayList arrayList2 = new ArrayList(list.size());
            this.c = arrayList2;
            this.b = Collections.unmodifiableList(arrayList2);
        } else {
            arrayList.clear();
        }
        for (int size = list.size() - 1; size >= 0; size--) {
            WindowInsetsAnimation windowInsetsAnimationJ = androidx.activity.result.contract.c.j(list.get(size));
            m0 m0VarA = a(windowInsetsAnimationJ);
            m0VarA.a.d(windowInsetsAnimationJ.getFraction());
            this.c.add(m0VarA);
        }
        return this.a.f(D0.h(null, windowInsets), this.b).g();
    }

    public final WindowInsetsAnimation.Bounds onStart(WindowInsetsAnimation windowInsetsAnimation, WindowInsetsAnimation.Bounds bounds) {
        AbstractC1047f0 abstractC1047f0 = this.a;
        a(windowInsetsAnimation);
        androidx.work.impl.model.e eVarG = abstractC1047f0.g(new androidx.work.impl.model.e(bounds));
        eVarG.getClass();
        androidx.activity.result.contract.c.l();
        return androidx.activity.result.contract.c.h(((androidx.core.graphics.e) eVarG.b).d(), ((androidx.core.graphics.e) eVarG.c).d());
    }
}
