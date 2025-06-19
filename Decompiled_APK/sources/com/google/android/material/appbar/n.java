package com.google.android.material.appbar;

import android.view.View;
import androidx.core.view.V;
import java.util.WeakHashMap;

/* loaded from: classes2.dex */
public final class n {
    public final View a;
    public int b;
    public int c;
    public int d;

    public n(View view) {
        this.a = view;
    }

    public final void a() {
        int i = this.d;
        View view = this.a;
        int top = i - (view.getTop() - this.b);
        WeakHashMap weakHashMap = V.a;
        view.offsetTopAndBottom(top);
        view.offsetLeftAndRight(0 - (view.getLeft() - this.c));
    }

    public final boolean b(int i) {
        if (this.d == i) {
            return false;
        }
        this.d = i;
        a();
        return true;
    }
}
