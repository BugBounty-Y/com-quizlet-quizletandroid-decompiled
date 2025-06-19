package com.quizlet.baserecyclerview;

import android.content.Context;
import android.view.View;
import androidx.recyclerview.widget.F0;
import com.braze.requests.framework.o;
import kotlin.jvm.internal.Intrinsics;
import kotlin.l;
import kotlin.u;

/* loaded from: classes2.dex */
public abstract class c extends F0 {
    public final View a;
    public final Context b;
    public final u c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(View view) {
        super(view);
        Intrinsics.checkNotNullParameter(view, "view");
        this.a = view;
        this.b = view.getContext();
        this.c = l.b(new o(this, 21));
    }

    public abstract void c(Object obj);

    public abstract androidx.viewbinding.a d();

    public final androidx.viewbinding.a e() {
        return (androidx.viewbinding.a) this.c.getValue();
    }
}
