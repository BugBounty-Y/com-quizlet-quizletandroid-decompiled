package com.google.android.material.tabs;

import android.graphics.drawable.Drawable;
import android.text.TextUtils;
import android.view.View;

/* loaded from: classes2.dex */
public final class g {
    public Integer a;
    public Drawable b;
    public CharSequence c;
    public CharSequence d;
    public int e;
    public View f;
    public l g;
    public j h;

    public final void a(CharSequence charSequence) {
        if (TextUtils.isEmpty(this.d) && !TextUtils.isEmpty(charSequence)) {
            this.h.setContentDescription(charSequence);
        }
        this.c = charSequence;
        j jVar = this.h;
        if (jVar != null) {
            jVar.e();
        }
    }
}
