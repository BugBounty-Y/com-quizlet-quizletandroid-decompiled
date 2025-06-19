package com.quizlet.quizletandroid.databinding;

import android.view.View;
import androidx.appcompat.widget.Toolbar;
import androidx.camera.view.PreviewView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.partskit.widgets.QTextView;

/* loaded from: classes3.dex */
public final class e0 implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final PreviewView b;
    public final QButton c;
    public final QTextView d;
    public final Toolbar e;

    public e0(ConstraintLayout constraintLayout, PreviewView previewView, QButton qButton, QTextView qTextView, Toolbar toolbar) {
        this.a = constraintLayout;
        this.b = previewView;
        this.c = qButton;
        this.d = qTextView;
        this.e = toolbar;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
