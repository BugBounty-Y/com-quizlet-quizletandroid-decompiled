package com.quizlet.explanations.textbook.ui.composables;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.fragment.app.FragmentContainerView;
import com.quizlet.explanations.databinding.l;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class c extends C4956o implements kotlin.jvm.functions.c {
    public static final c a = new c(3, l.class, "inflate", "inflate(Landroid/view/LayoutInflater;Landroid/view/ViewGroup;Z)Lcom/quizlet/explanations/databinding/FragmentTextbookLayoutBinding;", 0);

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        LayoutInflater p0 = (LayoutInflater) obj;
        ViewGroup viewGroup = (ViewGroup) obj2;
        boolean zBooleanValue = ((Boolean) obj3).booleanValue();
        Intrinsics.checkNotNullParameter(p0, "p0");
        View viewInflate = p0.inflate(R.layout.fragment_textbook_layout, viewGroup, false);
        if (zBooleanValue) {
            viewGroup.addView(viewInflate);
        }
        if (viewInflate == null) {
            throw new NullPointerException("rootView");
        }
        FragmentContainerView fragmentContainerView = (FragmentContainerView) viewInflate;
        return new l(fragmentContainerView, fragmentContainerView);
    }
}
