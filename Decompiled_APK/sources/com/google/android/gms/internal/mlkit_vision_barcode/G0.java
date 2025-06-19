package com.google.android.gms.internal.mlkit_vision_barcode;

import android.view.View;
import android.view.ViewGroup;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class G0 {
    public static final /* synthetic */ int a = 0;

    public static final androidx.compose.material.ripple.h a(ViewGroup viewGroup) {
        int childCount = viewGroup.getChildCount();
        for (int i = 0; i < childCount; i++) {
            View childAt = viewGroup.getChildAt(i);
            if (childAt instanceof androidx.compose.material.ripple.h) {
                return (androidx.compose.material.ripple.h) childAt;
            }
        }
        androidx.compose.material.ripple.h hVar = new androidx.compose.material.ripple.h(viewGroup.getContext());
        viewGroup.addView(hVar);
        return hVar;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v3, types: [android.view.ViewParent] */
    public static final ViewGroup b(View view) {
        while (!(view instanceof ViewGroup)) {
            ?? parent = view.getParent();
            if (!(parent instanceof View)) {
                throw new IllegalArgumentException(("Couldn't find a valid parent for " + view + ". Are you overriding LocalView and providing a View that is not attached to the view hierarchy?").toString());
            }
            view = parent;
        }
        return (ViewGroup) view;
    }

    public static final com.quizlet.ui.models.content.listitem.o c(com.quizlet.data.model.B0 b0) {
        if (b0 instanceof com.quizlet.data.model.C0) {
            com.quizlet.data.model.C0 c0 = (com.quizlet.data.model.C0) b0;
            Intrinsics.checkNotNullParameter(c0, "<this>");
            return new com.quizlet.ui.models.content.listitem.k(new com.quizlet.ui.models.content.listitem.c(c0.d, c0.g), c0.d, c0.f, 24);
        }
        if (b0 instanceof com.quizlet.data.model.D0) {
            com.quizlet.data.model.D0 d0 = (com.quizlet.data.model.D0) b0;
            Intrinsics.checkNotNullParameter(d0, "<this>");
            return new com.quizlet.ui.models.content.listitem.n(new com.quizlet.ui.models.content.listitem.p(d0.b, d0.c, d0.e, d0.i), d0.b, d0.g, 24);
        }
        if (!(b0 instanceof com.quizlet.data.model.E0)) {
            throw new IllegalArgumentException("Unknown MyExplanationsItem type");
        }
        com.quizlet.data.model.E0 e0 = (com.quizlet.data.model.E0) b0;
        return new com.quizlet.ui.models.content.listitem.m(X5.g(e0), e0.b, e0.g, 24);
    }
}
