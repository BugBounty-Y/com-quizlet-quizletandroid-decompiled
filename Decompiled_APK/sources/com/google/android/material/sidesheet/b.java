package com.google.android.material.sidesheet;

import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.core.graphics.e;
import androidx.core.view.D0;
import androidx.core.view.InterfaceC1062t;
import androidx.core.view.accessibility.n;
import androidx.core.view.z0;
import com.google.android.material.appbar.AppBarLayout;
import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.quizlet.quizletandroid.databinding.C4600d;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class b implements n, InterfaceC1062t {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ b(Object obj, int i) {
        this.b = obj;
        this.a = i;
    }

    @Override // androidx.core.view.accessibility.n
    public boolean g(View view) {
        ((SideSheetBehavior) this.b).w(this.a);
        return true;
    }

    @Override // androidx.core.view.InterfaceC1062t
    public D0 w(D0 d0, View view) {
        z0 z0Var = d0.a;
        e eVarG = z0Var.g(647);
        e eVarG2 = z0Var.g(8);
        Intrinsics.d(view);
        view.setPadding(view.getPaddingLeft(), eVarG.b, view.getPaddingRight(), view.getPaddingBottom());
        C4600d c4600d = (C4600d) this.b;
        AppBarLayout appbar = (AppBarLayout) c4600d.c.b;
        Intrinsics.checkNotNullExpressionValue(appbar, "appbar");
        int paddingTop = appbar.getPaddingTop();
        int paddingBottom = appbar.getPaddingBottom();
        int i = eVarG.a;
        int i2 = eVarG.c;
        appbar.setPadding(i, paddingTop, i2, paddingBottom);
        FrameLayout editSetFragmentContainer = c4600d.f;
        Intrinsics.checkNotNullExpressionValue(editSetFragmentContainer, "editSetFragmentContainer");
        editSetFragmentContainer.setPadding(i, editSetFragmentContainer.getPaddingTop(), i2, editSetFragmentContainer.getPaddingBottom());
        FloatingActionButton addCardFab = c4600d.b;
        Intrinsics.checkNotNullExpressionValue(addCardFab, "addCardFab");
        ViewGroup.LayoutParams layoutParams = addCardFab.getLayoutParams();
        if (layoutParams == null) {
            throw new NullPointerException("null cannot be cast to non-null type android.view.ViewGroup.MarginLayoutParams");
        }
        ViewGroup.MarginLayoutParams marginLayoutParams = (ViewGroup.MarginLayoutParams) layoutParams;
        int i3 = this.a;
        marginLayoutParams.topMargin = i3;
        marginLayoutParams.bottomMargin = eVarG.d + i3 + eVarG2.d;
        marginLayoutParams.leftMargin = i + i3;
        marginLayoutParams.rightMargin = i3 + i2;
        addCardFab.setLayoutParams(marginLayoutParams);
        return d0;
    }
}
