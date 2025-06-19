package com.google.android.material.snackbar;

import android.content.Context;
import android.text.TextUtils;
import android.view.View;
import android.view.ViewGroup;
import android.view.accessibility.AccessibilityManager;
import android.widget.Button;
import com.quizlet.quizletandroid.R;

/* loaded from: classes2.dex */
public final class h extends g {
    public static final int[] E = {R.attr.snackbarButtonStyle, R.attr.snackbarTextViewStyle};
    public final AccessibilityManager B;
    public boolean C;
    public com.quizlet.quizletandroid.ui.setcreation.fragments.i D;

    public h(Context context, ViewGroup viewGroup, SnackbarContentLayout snackbarContentLayout, SnackbarContentLayout snackbarContentLayout2) {
        super(context, viewGroup, snackbarContentLayout, snackbarContentLayout2);
        this.B = (AccessibilityManager) viewGroup.getContext().getSystemService("accessibility");
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x001e  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x002c A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:33:0x002a A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:35:? A[LOOP:0: B:3:0x0002->B:35:?, LOOP_END, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.google.android.material.snackbar.h g(android.view.View r7, java.lang.CharSequence r8) {
        /*
            r0 = 0
            r1 = r0
        L2:
            boolean r2 = r7 instanceof androidx.coordinatorlayout.widget.CoordinatorLayout
            if (r2 == 0) goto L9
            android.view.ViewGroup r7 = (android.view.ViewGroup) r7
            goto L2d
        L9:
            boolean r2 = r7 instanceof android.widget.FrameLayout
            if (r2 == 0) goto L1c
            int r1 = r7.getId()
            r2 = 16908290(0x1020002, float:2.3877235E-38)
            if (r1 != r2) goto L19
            android.view.ViewGroup r7 = (android.view.ViewGroup) r7
            goto L2d
        L19:
            r1 = r7
            android.view.ViewGroup r1 = (android.view.ViewGroup) r1
        L1c:
            if (r7 == 0) goto L2a
            android.view.ViewParent r7 = r7.getParent()
            boolean r2 = r7 instanceof android.view.View
            if (r2 == 0) goto L29
            android.view.View r7 = (android.view.View) r7
            goto L2a
        L29:
            r7 = r0
        L2a:
            if (r7 != 0) goto L2
            r7 = r1
        L2d:
            if (r7 == 0) goto L73
            android.content.Context r0 = r7.getContext()
            android.view.LayoutInflater r1 = android.view.LayoutInflater.from(r0)
            int[] r2 = com.google.android.material.snackbar.h.E
            android.content.res.TypedArray r2 = r0.obtainStyledAttributes(r2)
            r3 = 0
            r4 = -1
            int r5 = r2.getResourceId(r3, r4)
            r6 = 1
            int r6 = r2.getResourceId(r6, r4)
            r2.recycle()
            if (r5 == r4) goto L53
            if (r6 == r4) goto L53
            r2 = 2131624897(0x7f0e03c1, float:1.8876987E38)
            goto L56
        L53:
            r2 = 2131624346(0x7f0e019a, float:1.887587E38)
        L56:
            android.view.View r1 = r1.inflate(r2, r7, r3)
            com.google.android.material.snackbar.SnackbarContentLayout r1 = (com.google.android.material.snackbar.SnackbarContentLayout) r1
            com.google.android.material.snackbar.h r2 = new com.google.android.material.snackbar.h
            r2.<init>(r0, r7, r1, r1)
            com.google.android.material.snackbar.f r7 = r2.i
            android.view.View r7 = r7.getChildAt(r3)
            com.google.android.material.snackbar.SnackbarContentLayout r7 = (com.google.android.material.snackbar.SnackbarContentLayout) r7
            android.widget.TextView r7 = r7.getMessageView()
            r7.setText(r8)
            r2.k = r3
            return r2
        L73:
            java.lang.IllegalArgumentException r7 = new java.lang.IllegalArgumentException
            java.lang.String r8 = "No suitable parent found from the given view. Please provide a valid view."
            r7.<init>(r8)
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.snackbar.h.g(android.view.View, java.lang.CharSequence):com.google.android.material.snackbar.h");
    }

    public final void h(String str, View.OnClickListener onClickListener) {
        Button actionView = ((SnackbarContentLayout) this.i.getChildAt(0)).getActionView();
        if (TextUtils.isEmpty(str) || onClickListener == null) {
            actionView.setVisibility(8);
            actionView.setOnClickListener(null);
            this.C = false;
        } else {
            this.C = true;
            actionView.setVisibility(0);
            actionView.setText(str);
            actionView.setOnClickListener(new com.braze.ui.inappmessage.views.a(5, this, onClickListener));
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:4:0x000b  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void i() {
        /*
            r8 = this;
            com.quizlet.data.repository.achievements.h r0 = com.quizlet.data.repository.achievements.h.c()
            int r1 = r8.k
            r2 = 0
            r3 = 4
            r4 = -2
            if (r1 != r4) goto Ld
        Lb:
            r1 = r4
            goto L2e
        Ld:
            int r5 = android.os.Build.VERSION.SDK_INT
            android.view.accessibility.AccessibilityManager r6 = r8.B
            r7 = 29
            if (r5 < r7) goto L23
            boolean r4 = r8.C
            if (r4 == 0) goto L1b
            r4 = r3
            goto L1c
        L1b:
            r4 = r2
        L1c:
            r4 = r4 | 3
            int r1 = com.bumptech.glide.load.model.stream.g.a(r6, r1, r4)
            goto L2e
        L23:
            boolean r5 = r8.C
            if (r5 == 0) goto L2e
            boolean r5 = r6.isTouchExplorationEnabled()
            if (r5 == 0) goto L2e
            goto Lb
        L2e:
            com.google.android.material.snackbar.e r4 = r8.u
            java.lang.Object r5 = r0.a
            monitor-enter(r5)
            boolean r6 = r0.e(r4)     // Catch: java.lang.Throwable -> L4f
            if (r6 == 0) goto L51
            java.lang.Object r2 = r0.c     // Catch: java.lang.Throwable -> L4f
            com.google.android.material.snackbar.i r2 = (com.google.android.material.snackbar.i) r2     // Catch: java.lang.Throwable -> L4f
            r2.b = r1     // Catch: java.lang.Throwable -> L4f
            java.lang.Object r1 = r0.b     // Catch: java.lang.Throwable -> L4f
            android.os.Handler r1 = (android.os.Handler) r1     // Catch: java.lang.Throwable -> L4f
            r1.removeCallbacksAndMessages(r2)     // Catch: java.lang.Throwable -> L4f
            java.lang.Object r1 = r0.c     // Catch: java.lang.Throwable -> L4f
            com.google.android.material.snackbar.i r1 = (com.google.android.material.snackbar.i) r1     // Catch: java.lang.Throwable -> L4f
            r0.j(r1)     // Catch: java.lang.Throwable -> L4f
            monitor-exit(r5)     // Catch: java.lang.Throwable -> L4f
            return
        L4f:
            r0 = move-exception
            goto L86
        L51:
            java.lang.Object r6 = r0.d     // Catch: java.lang.Throwable -> L4f
            com.google.android.material.snackbar.i r6 = (com.google.android.material.snackbar.i) r6     // Catch: java.lang.Throwable -> L4f
            if (r6 == 0) goto L60
            java.lang.ref.WeakReference r6 = r6.a     // Catch: java.lang.Throwable -> L4f
            java.lang.Object r6 = r6.get()     // Catch: java.lang.Throwable -> L4f
            if (r6 != r4) goto L60
            r2 = 1
        L60:
            if (r2 == 0) goto L69
            java.lang.Object r2 = r0.d     // Catch: java.lang.Throwable -> L4f
            com.google.android.material.snackbar.i r2 = (com.google.android.material.snackbar.i) r2     // Catch: java.lang.Throwable -> L4f
            r2.b = r1     // Catch: java.lang.Throwable -> L4f
            goto L70
        L69:
            com.google.android.material.snackbar.i r2 = new com.google.android.material.snackbar.i     // Catch: java.lang.Throwable -> L4f
            r2.<init>(r1, r4)     // Catch: java.lang.Throwable -> L4f
            r0.d = r2     // Catch: java.lang.Throwable -> L4f
        L70:
            java.lang.Object r1 = r0.c     // Catch: java.lang.Throwable -> L4f
            com.google.android.material.snackbar.i r1 = (com.google.android.material.snackbar.i) r1     // Catch: java.lang.Throwable -> L4f
            if (r1 == 0) goto L7e
            boolean r1 = r0.a(r1, r3)     // Catch: java.lang.Throwable -> L4f
            if (r1 == 0) goto L7e
            monitor-exit(r5)     // Catch: java.lang.Throwable -> L4f
            return
        L7e:
            r1 = 0
            r0.c = r1     // Catch: java.lang.Throwable -> L4f
            r0.k()     // Catch: java.lang.Throwable -> L4f
            monitor-exit(r5)     // Catch: java.lang.Throwable -> L4f
            return
        L86:
            monitor-exit(r5)     // Catch: java.lang.Throwable -> L4f
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.material.snackbar.h.i():void");
    }
}
