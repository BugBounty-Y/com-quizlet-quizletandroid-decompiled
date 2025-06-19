package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.ScrollView;
import androidx.appcompat.widget.AppCompatTextView;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.partskit.widgets.QTextView;

/* renamed from: com.quizlet.quizletandroid.databinding.s, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4614s implements androidx.viewbinding.a {
    public final ScrollView a;
    public final AppCompatTextView b;
    public final QButton c;
    public final QButton d;
    public final QTextView e;
    public final com.quizlet.features.infra.legacyadapter.databinding.f f;

    public C4614s(ScrollView scrollView, AppCompatTextView appCompatTextView, QButton qButton, QButton qButton2, QTextView qTextView, com.quizlet.features.infra.legacyadapter.databinding.f fVar) {
        this.a = scrollView;
        this.b = appCompatTextView;
        this.c = qButton;
        this.d = qButton2;
        this.e = qTextView;
        this.f = fVar;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
