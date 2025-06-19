package com.onetrust.otpublishers.headless.databinding;

import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.appcompat.widget.AppCompatButton;
import androidx.appcompat.widget.SearchView;
import androidx.appcompat.widget.SwitchCompat;
import androidx.cardview.widget.CardView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.constraintlayout.widget.Group;
import androidx.recyclerview.widget.RecyclerView;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.uicommon.ui.common.views.QuizletPlusLogo;

/* loaded from: classes2.dex */
public final class g implements androidx.viewbinding.a {
    public final /* synthetic */ int a = 0;
    public final View b;
    public final ViewGroup c;
    public final View d;
    public final View e;
    public final TextView f;
    public final TextView g;
    public final View h;
    public final View i;
    public final View j;
    public final View k;
    public final TextView l;
    public final TextView m;
    public final View n;
    public final ViewGroup o;
    public final View p;
    public final TextView q;

    public g(RelativeLayout relativeLayout, TextView textView, SwitchCompat switchCompat, ImageView imageView, AppCompatButton appCompatButton, AppCompatButton appCompatButton2, AppCompatButton appCompatButton3, ImageView imageView2, RelativeLayout relativeLayout2, RecyclerView recyclerView, SearchView searchView, CardView cardView, TextView textView2, Button button, RelativeLayout relativeLayout3, View view) {
        this.c = relativeLayout;
        this.f = textView;
        this.h = switchCompat;
        this.i = imageView;
        this.k = appCompatButton;
        this.l = appCompatButton2;
        this.m = appCompatButton3;
        this.j = imageView2;
        this.d = relativeLayout2;
        this.n = recyclerView;
        this.o = searchView;
        this.p = cardView;
        this.g = textView2;
        this.q = button;
        this.e = relativeLayout3;
        this.b = view;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        switch (this.a) {
            case 0:
                return (RelativeLayout) this.c;
            default:
                return (ConstraintLayout) this.c;
        }
    }

    public g(ConstraintLayout constraintLayout, View view, View view2, QTextView qTextView, QTextView qTextView2, QTextView qTextView3, Group group, QTextView qTextView4, QTextView qTextView5, Group group2, QTextView qTextView6, QTextView qTextView7, QTextView qTextView8, QuizletPlusLogo quizletPlusLogo, View view3, QTextView qTextView9) {
        this.c = constraintLayout;
        this.b = view;
        this.d = view2;
        this.e = qTextView;
        this.f = qTextView2;
        this.g = qTextView3;
        this.h = group;
        this.i = qTextView4;
        this.j = qTextView5;
        this.k = group2;
        this.l = qTextView6;
        this.m = qTextView7;
        this.n = qTextView8;
        this.o = quizletPlusLogo;
        this.p = view3;
        this.q = qTextView9;
    }
}
