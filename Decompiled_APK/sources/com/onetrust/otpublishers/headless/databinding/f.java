package com.onetrust.otpublishers.headless.databinding;

import android.view.View;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.appcompat.widget.SearchView;
import androidx.appcompat.widget.SwitchCompat;
import androidx.recyclerview.widget.RecyclerView;

/* loaded from: classes2.dex */
public final class f implements androidx.viewbinding.a {
    public final RelativeLayout a;
    public final ImageView b;
    public final ImageView c;
    public final RecyclerView d;
    public final TextView e;
    public final SwitchCompat f;
    public final TextView g;
    public final RelativeLayout h;
    public final TextView i;
    public final SearchView j;

    public f(RelativeLayout relativeLayout, ImageView imageView, ImageView imageView2, RecyclerView recyclerView, TextView textView, SwitchCompat switchCompat, TextView textView2, RelativeLayout relativeLayout2, TextView textView3, SearchView searchView) {
        this.a = relativeLayout;
        this.b = imageView;
        this.c = imageView2;
        this.d = recyclerView;
        this.e = textView;
        this.f = switchCompat;
        this.g = textView2;
        this.h = relativeLayout2;
        this.i = textView3;
        this.j = searchView;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
