package androidx.appcompat.widget;

import android.content.Context;
import android.view.View;
import android.view.Window;
import androidx.appcompat.view.menu.C0064a;

/* loaded from: classes.dex */
public final class w1 implements View.OnClickListener {
    public final C0064a a;
    public final /* synthetic */ x1 b;

    public w1(x1 x1Var) {
        this.b = x1Var;
        Context context = x1Var.a.getContext();
        CharSequence charSequence = x1Var.h;
        C0064a c0064a = new C0064a();
        c0064a.e = 4096;
        c0064a.g = 4096;
        c0064a.l = null;
        c0064a.m = null;
        c0064a.n = false;
        c0064a.o = false;
        c0064a.p = 16;
        c0064a.i = context;
        c0064a.a = charSequence;
        this.a = c0064a;
    }

    @Override // android.view.View.OnClickListener
    public final void onClick(View view) {
        x1 x1Var = this.b;
        Window.Callback callback = x1Var.k;
        if (callback == null || !x1Var.l) {
            return;
        }
        callback.onMenuItemSelected(0, this.a);
    }
}
