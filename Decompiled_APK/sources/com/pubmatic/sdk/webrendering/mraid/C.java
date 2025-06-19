package com.pubmatic.sdk.webrendering.mraid;

import android.annotation.SuppressLint;
import android.content.Context;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.webkit.WebView;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public class C extends RelativeLayout implements View.OnTouchListener {
    private ViewGroup a;

    @NonNull
    private Context b;
    private com.pubmatic.sdk.common.view.c c;
    private B d;
    private ImageView e;
    private RelativeLayout f;
    private int g;
    private boolean h;
    private final ViewTreeObserver.OnGlobalLayoutListener i;
    private final com.pubmatic.sdk.common.view.b j;

    public C(@NonNull Context context) {
        super(context);
        this.h = true;
        this.i = new y(this);
        this.j = new z(this);
        this.b = context;
    }

    public void d() {
        ViewGroup viewGroup = this.a;
        if (viewGroup != null) {
            viewGroup.bringChildToFront(this);
            this.a.requestFocus();
        }
        getViewTreeObserver().addOnGlobalLayoutListener(this.i);
    }

    @Override // android.view.View.OnTouchListener
    @SuppressLint({"ClickableViewAccessibility"})
    public boolean onTouch(View view, MotionEvent motionEvent) {
        return !(view instanceof com.pubmatic.sdk.common.view.c);
    }

    public void a(@NonNull ViewGroup viewGroup, @NonNull com.pubmatic.sdk.common.view.c cVar, int i, int i2, int i3, int i4, B b) {
        this.c = cVar;
        this.b = cVar.getContext();
        this.a = viewGroup;
        this.d = b;
        a(cVar, i, i2, i3, i4);
        this.g = com.pubmatic.sdk.common.utility.o.getDeviceOrientation(this.b);
    }

    public void b() {
        com.pubmatic.sdk.common.view.c cVar;
        RelativeLayout relativeLayout = this.f;
        if (relativeLayout != null && this.c != null) {
            relativeLayout.getViewTreeObserver().removeOnGlobalLayoutListener(this.i);
            this.f.removeView(this.e);
            this.f.removeView(this.c);
            this.c.setWebViewBackPress(null);
        }
        setOnTouchListener(null);
        removeAllViews();
        B b = this.d;
        if (b == null || (cVar = this.c) == null) {
            return;
        }
        b.a(cVar);
    }

    public ImageView c() {
        return this.e;
    }

    @SuppressLint({"ClickableViewAccessibility"})
    private void a(@NonNull WebView webView, int i, int i2, int i3, int i4) {
        this.e = com.pubmatic.sdk.webrendering.a.createSkipButton(getContext(), com.pubmatic.sdk.webrendering.e.pob_close_btn, com.pubmatic.sdk.webrendering.d.pob_ic_close_black_24dp);
        RelativeLayout.LayoutParams layoutParams = new RelativeLayout.LayoutParams(-2, -2);
        layoutParams.addRule(11);
        this.e.setOnClickListener(new A(this));
        this.f = new RelativeLayout(this.b);
        RelativeLayout.LayoutParams layoutParams2 = new RelativeLayout.LayoutParams(i, i2);
        layoutParams2.setMargins(i3, i4, Integer.MIN_VALUE, Integer.MIN_VALUE);
        this.f.addView(webView, new RelativeLayout.LayoutParams(-1, -1));
        this.f.addView(this.e, layoutParams);
        addView(this.f, layoutParams2);
        a(true);
        setOnTouchListener(this);
        RelativeLayout.LayoutParams layoutParams3 = new RelativeLayout.LayoutParams(-1, -1);
        ViewGroup viewGroup = this.a;
        if (viewGroup != null) {
            viewGroup.addView(this, 0, layoutParams3);
        }
    }

    public void a(boolean z) {
        com.pubmatic.sdk.common.view.c cVar = this.c;
        if (cVar != null) {
            if (z) {
                cVar.setWebViewBackPress(this.j);
            } else {
                cVar.setWebViewBackPress(null);
            }
        }
    }

    public void a(int i, int i2, int i3, int i4) {
        if (this.f != null) {
            RelativeLayout.LayoutParams layoutParams = new RelativeLayout.LayoutParams(i, i2);
            layoutParams.setMargins(i3, i4, Integer.MIN_VALUE, Integer.MIN_VALUE);
            updateViewLayout(this.f, layoutParams);
        }
    }

    public void a() {
        this.h = false;
    }
}
