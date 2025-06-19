package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import com.quizlet.assembly.widgets.toggle.AssemblyToggleSwitch;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.uicommon.ui.common.widgets.QSegmentedControl;

/* loaded from: classes3.dex */
public final class p0 implements androidx.viewbinding.a {
    public final ScrollView a;
    public final AssemblyToggleSwitch b;
    public final LinearLayout c;
    public final QSegmentedControl d;
    public final FrameLayout e;
    public final AssemblyToggleSwitch f;
    public final QTextView g;
    public final QTextView h;
    public final AssemblyToggleSwitch i;
    public final AssemblyToggleSwitch j;

    public p0(ScrollView scrollView, AssemblyToggleSwitch assemblyToggleSwitch, LinearLayout linearLayout, QSegmentedControl qSegmentedControl, FrameLayout frameLayout, AssemblyToggleSwitch assemblyToggleSwitch2, QTextView qTextView, QTextView qTextView2, AssemblyToggleSwitch assemblyToggleSwitch3, AssemblyToggleSwitch assemblyToggleSwitch4) {
        this.a = scrollView;
        this.b = assemblyToggleSwitch;
        this.c = linearLayout;
        this.d = qSegmentedControl;
        this.e = frameLayout;
        this.f = assemblyToggleSwitch2;
        this.g = qTextView;
        this.h = qTextView2;
        this.i = assemblyToggleSwitch3;
        this.j = assemblyToggleSwitch4;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
