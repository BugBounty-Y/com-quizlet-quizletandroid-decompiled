package com.quizlet.quizletandroid.ui.setcreation.managers;

import android.view.View;
import android.view.ViewPropertyAnimator;
import androidx.coordinatorlayout.widget.CoordinatorLayout;

/* loaded from: classes3.dex */
public class CardVisibilityFABBehavior extends androidx.coordinatorlayout.widget.b {
    public ViewPropertyAnimator a;
    public int b;
    public com.quizlet.login.authentication.login.a c;

    @Override // androidx.coordinatorlayout.widget.b
    public final boolean f(CoordinatorLayout coordinatorLayout, View view, View view2) {
        return view2.getId() == this.b;
    }

    /* JADX WARN: Removed duplicated region for block: B:4:0x000a  */
    @Override // androidx.coordinatorlayout.widget.b
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean h(androidx.coordinatorlayout.widget.CoordinatorLayout r7, android.view.View r8, android.view.View r9) {
        /*
            r6 = this;
            com.google.android.material.floatingactionbutton.FloatingActionButton r8 = (com.google.android.material.floatingactionbutton.FloatingActionButton) r8
            android.content.Context r7 = r9.getContext()
            r0 = 1
            r1 = 0
            if (r7 != 0) goto Lc
        La:
            r7 = r1
            goto L31
        Lc:
            android.graphics.Rect r2 = new android.graphics.Rect
            r2.<init>()
            r9.getGlobalVisibleRect(r2)
            java.lang.String r9 = "window"
            java.lang.Object r7 = r7.getSystemService(r9)
            android.view.WindowManager r7 = (android.view.WindowManager) r7
            android.util.DisplayMetrics r9 = new android.util.DisplayMetrics
            r9.<init>()
            if (r7 == 0) goto L2a
            android.view.Display r7 = r7.getDefaultDisplay()
            r7.getMetrics(r9)
        L2a:
            int r7 = r2.bottom
            int r9 = r9.heightPixels
            if (r7 < r9) goto La
            r7 = r0
        L31:
            r9 = 1065353216(0x3f800000, float:1.0)
            if (r7 == 0) goto L64
            float r2 = r8.getScaleX()
            int r2 = (r2 > r9 ? 1 : (r2 == r9 ? 0 : -1))
            if (r2 < 0) goto L3e
            goto L64
        L3e:
            android.view.ViewPropertyAnimator r2 = r6.a
            if (r2 == 0) goto L4d
            long r2 = r2.getDuration()
            r4 = 201(0xc9, double:9.93E-322)
            int r2 = (r2 > r4 ? 1 : (r2 == r4 ? 0 : -1))
            if (r2 != 0) goto L4d
            goto L64
        L4d:
            r8.clearAnimation()
            com.google.firebase.messaging.r r7 = new com.google.firebase.messaging.r
            r7.<init>(r6, r8, r0)
            r8.post(r7)
            com.quizlet.login.authentication.login.a r7 = r6.c
            if (r7 == 0) goto L93
            java.lang.Object r7 = r7.b
            com.quizlet.quizletandroid.ui.setcreation.fragments.EditSetFragment r7 = (com.quizlet.quizletandroid.ui.setcreation.fragments.EditSetFragment) r7
            r7.X(r1)
            return r0
        L64:
            if (r7 != 0) goto L94
            float r7 = r8.getScaleX()
            int r7 = (r7 > r9 ? 1 : (r7 == r9 ? 0 : -1))
            if (r7 < 0) goto L94
            android.view.ViewPropertyAnimator r7 = r6.a
            if (r7 == 0) goto L7d
            long r2 = r7.getDuration()
            r4 = 200(0xc8, double:9.9E-322)
            int r7 = (r2 > r4 ? 1 : (r2 == r4 ? 0 : -1))
            if (r7 != 0) goto L7d
            goto L94
        L7d:
            r8.clearAnimation()
            com.google.firebase.messaging.r r7 = new com.google.firebase.messaging.r
            r7.<init>(r6, r8, r1)
            r8.post(r7)
            com.quizlet.login.authentication.login.a r7 = r6.c
            if (r7 == 0) goto L93
            java.lang.Object r7 = r7.b
            com.quizlet.quizletandroid.ui.setcreation.fragments.EditSetFragment r7 = (com.quizlet.quizletandroid.ui.setcreation.fragments.EditSetFragment) r7
            r7.X(r0)
        L93:
            return r0
        L94:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.setcreation.managers.CardVisibilityFABBehavior.h(androidx.coordinatorlayout.widget.CoordinatorLayout, android.view.View, android.view.View):boolean");
    }
}
