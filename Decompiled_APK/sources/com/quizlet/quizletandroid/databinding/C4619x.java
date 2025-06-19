package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.RelativeLayout;
import androidx.recyclerview.widget.RecyclerView;
import com.quizlet.richtext.ui.toolbar.QRichTextToolbar;

/* renamed from: com.quizlet.quizletandroid.databinding.x, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4619x implements androidx.viewbinding.a {
    public final RelativeLayout a;
    public final RecyclerView b;
    public final QRichTextToolbar c;

    public C4619x(RelativeLayout relativeLayout, RecyclerView recyclerView, QRichTextToolbar qRichTextToolbar) {
        this.a = relativeLayout;
        this.b = recyclerView;
        this.c = qRichTextToolbar;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
