package androidx.appcompat.widget;

import android.content.Context;
import android.view.View;
import com.quizlet.quizletandroid.R;

/* renamed from: androidx.appcompat.widget.h, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0087h extends androidx.appcompat.view.menu.x {
    public final /* synthetic */ int l = 0;
    public final /* synthetic */ C0095l m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0087h(C0095l c0095l, Context context, androidx.appcompat.view.menu.n nVar, View view) {
        super(R.attr.actionOverflowMenuStyle, context, view, nVar, true);
        this.m = c0095l;
        this.f = 8388613;
        com.google.android.gms.auth.api.signin.internal.h hVar = c0095l.w;
        this.h = hVar;
        androidx.appcompat.view.menu.v vVar = this.i;
        if (vVar != null) {
            vVar.c(hVar);
        }
    }

    @Override // androidx.appcompat.view.menu.x
    public final void c() {
        switch (this.l) {
            case 0:
                C0095l c0095l = this.m;
                c0095l.t = null;
                c0095l.getClass();
                super.c();
                break;
            default:
                C0095l c0095l2 = this.m;
                androidx.appcompat.view.menu.n nVar = c0095l2.c;
                if (nVar != null) {
                    nVar.c(true);
                }
                c0095l2.s = null;
                super.c();
                break;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C0087h(C0095l c0095l, Context context, androidx.appcompat.view.menu.F f, View view) {
        super(R.attr.actionOverflowMenuStyle, context, view, f, false);
        this.m = c0095l;
        if ((f.A.x & 32) != 32) {
            View view2 = c0095l.i;
            this.e = view2 == null ? (View) c0095l.h : view2;
        }
        com.google.android.gms.auth.api.signin.internal.h hVar = c0095l.w;
        this.h = hVar;
        androidx.appcompat.view.menu.v vVar = this.i;
        if (vVar != null) {
            vVar.c(hVar);
        }
    }
}
