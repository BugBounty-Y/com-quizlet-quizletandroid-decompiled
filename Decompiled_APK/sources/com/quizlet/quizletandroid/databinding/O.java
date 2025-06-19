package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.ScrollView;
import com.quizlet.assembly.widgets.toggle.AssemblyToggleSwitch;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.uicommon.ui.common.widgets.QSegmentedControl;

/* loaded from: classes3.dex */
public final class O implements androidx.viewbinding.a {
    public final ScrollView a;
    public final AssemblyToggleSwitch b;
    public final RelativeLayout c;
    public final LinearLayout d;
    public final AssemblyToggleSwitch e;
    public final RelativeLayout f;
    public final QTextView g;
    public final QTextView h;
    public final RelativeLayout i;
    public final QTextView j;
    public final QSegmentedControl k;
    public final AssemblyToggleSwitch l;
    public final RelativeLayout m;

    public O(ScrollView scrollView, AssemblyToggleSwitch assemblyToggleSwitch, RelativeLayout relativeLayout, LinearLayout linearLayout, AssemblyToggleSwitch assemblyToggleSwitch2, RelativeLayout relativeLayout2, QTextView qTextView, QTextView qTextView2, RelativeLayout relativeLayout3, QTextView qTextView3, QSegmentedControl qSegmentedControl, AssemblyToggleSwitch assemblyToggleSwitch3, RelativeLayout relativeLayout4) {
        this.a = scrollView;
        this.b = assemblyToggleSwitch;
        this.c = relativeLayout;
        this.d = linearLayout;
        this.e = assemblyToggleSwitch2;
        this.f = relativeLayout2;
        this.g = qTextView;
        this.h = qTextView2;
        this.i = relativeLayout3;
        this.j = qTextView3;
        this.k = qSegmentedControl;
        this.l = assemblyToggleSwitch3;
        this.m = relativeLayout4;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
