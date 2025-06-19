package com.onetrust.otpublishers.headless.databinding;

import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.appcompat.widget.SwitchCompat;
import com.quizlet.assembly.widgets.AssemblyCard;
import com.quizlet.assembly.widgets.AssemblyPill;
import com.quizlet.upgrade.ui.widgets.UpgradePlanChoiceCard;

/* loaded from: classes2.dex */
public final class e implements androidx.viewbinding.a {
    public final /* synthetic */ int a = 0;
    public final ViewGroup b;
    public final View c;
    public final TextView d;
    public final View e;
    public final TextView f;
    public final ViewGroup g;
    public final View h;
    public final TextView i;

    public e(RelativeLayout relativeLayout, TextView textView, RelativeLayout relativeLayout2, TextView textView2, TextView textView3, SwitchCompat switchCompat, View view, TextView textView4) {
        this.b = relativeLayout;
        this.d = textView;
        this.g = relativeLayout2;
        this.f = textView2;
        this.h = textView3;
        this.c = switchCompat;
        this.e = view;
        this.i = textView4;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        switch (this.a) {
            case 0:
                return (RelativeLayout) this.b;
            case 1:
                return (RelativeLayout) this.b;
            default:
                return (UpgradePlanChoiceCard) this.b;
        }
    }

    public e(RelativeLayout relativeLayout, SwitchCompat switchCompat, ImageView imageView, SwitchCompat switchCompat2, TextView textView, View view, TextView textView2, RelativeLayout relativeLayout2) {
        this.b = relativeLayout;
        this.c = switchCompat;
        this.h = imageView;
        this.i = switchCompat2;
        this.d = textView;
        this.e = view;
        this.f = textView2;
        this.g = relativeLayout2;
    }

    public e(UpgradePlanChoiceCard upgradePlanChoiceCard, AssemblyPill assemblyPill, AssemblyCard assemblyCard, TextView textView, TextView textView2, TextView textView3, TextView textView4, ImageView imageView) {
        this.b = upgradePlanChoiceCard;
        this.g = assemblyPill;
        this.c = assemblyCard;
        this.d = textView;
        this.f = textView2;
        this.h = textView3;
        this.i = textView4;
        this.e = imageView;
    }
}
