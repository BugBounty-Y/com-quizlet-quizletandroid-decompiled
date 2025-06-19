package androidx.appcompat.view.menu;

import android.content.Context;
import android.graphics.Point;
import android.graphics.Rect;
import android.view.Display;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import com.quizlet.quizletandroid.R;

/* loaded from: classes.dex */
public class x {
    public final Context a;
    public final n b;
    public final boolean c;
    public final int d;
    public View e;
    public boolean g;
    public y h;
    public v i;
    public w j;
    public int f = 8388611;
    public final w k = new w(this);

    public x(int i, Context context, View view, n nVar, boolean z) {
        this.a = context;
        this.b = nVar;
        this.e = view;
        this.c = z;
        this.d = i;
    }

    public final v a() {
        v e;
        if (this.i == null) {
            Context context = this.a;
            Display defaultDisplay = ((WindowManager) context.getSystemService("window")).getDefaultDisplay();
            Point point = new Point();
            defaultDisplay.getRealSize(point);
            if (Math.min(point.x, point.y) >= context.getResources().getDimensionPixelSize(R.dimen.abc_cascading_menus_min_smallest_width)) {
                e = new h(context, this.e, this.d, this.c);
            } else {
                View view = this.e;
                Context context2 = this.a;
                boolean z = this.c;
                e = new E(this.d, context2, view, this.b, z);
            }
            e.l(this.b);
            e.r(this.k);
            e.n(this.e);
            e.c(this.h);
            e.o(this.g);
            e.p(this.f);
            this.i = e;
        }
        return this.i;
    }

    public final boolean b() {
        v vVar = this.i;
        return vVar != null && vVar.a();
    }

    public void c() {
        this.i = null;
        w wVar = this.j;
        if (wVar != null) {
            wVar.onDismiss();
        }
    }

    public final void d(int i, int i2, boolean z, boolean z2) {
        v vVarA = a();
        vVarA.s(z2);
        if (z) {
            if ((Gravity.getAbsoluteGravity(this.f, this.e.getLayoutDirection()) & 7) == 5) {
                i -= this.e.getWidth();
            }
            vVarA.q(i);
            vVarA.t(i2);
            int i3 = (int) ((this.a.getResources().getDisplayMetrics().density * 48.0f) / 2.0f);
            vVarA.a = new Rect(i - i3, i2 - i3, i + i3, i2 + i3);
        }
        vVarA.f();
    }
}
