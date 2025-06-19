package com.quizlet.partskit.widgets;

import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.compose.ui.text.font.m;
import androidx.core.content.res.k;
import com.google.android.material.tabs.g;
import com.google.android.material.tabs.l;
import com.quizlet.ui.resources.designsystem.generated.a;

/* loaded from: classes3.dex */
public class QTabLayout extends l {
    public QTabLayout(Context context) {
        super(context);
    }

    @Override // com.google.android.material.tabs.l
    public final void a(g gVar) {
        super.a(gVar);
        r(gVar.e);
    }

    @Override // com.google.android.material.tabs.l
    public final void b(g gVar, int i, boolean z) {
        super.b(gVar, i, z);
        r(i);
    }

    @Override // com.google.android.material.tabs.l
    public final void c(g gVar, boolean z) {
        super.c(gVar, z);
        r(gVar.e);
    }

    public final void r(int i) {
        ViewGroup viewGroup = (ViewGroup) ((ViewGroup) getChildAt(0)).getChildAt(i);
        int childCount = viewGroup.getChildCount();
        for (int i2 = 0; i2 < childCount; i2++) {
            View childAt = viewGroup.getChildAt(i2);
            if (childAt instanceof TextView) {
                Context context = getContext();
                m mVar = a.a;
                ((TextView) childAt).setTypeface(k.a(context, a.d), 0);
            }
        }
    }

    public QTabLayout(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
    }
}
