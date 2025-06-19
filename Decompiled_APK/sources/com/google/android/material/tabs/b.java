package com.google.android.material.tabs;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.drawable.Drawable;
import android.view.View;

/* loaded from: classes2.dex */
public class b extends View {
    public final CharSequence a;
    public final Drawable b;
    public final int c;

    public b(Context context) {
        super(context, null);
        com.quizlet.data.repository.classfolder.e eVarL = com.quizlet.data.repository.classfolder.e.l(context, null, com.google.android.material.a.O);
        TypedArray typedArray = (TypedArray) eVarL.c;
        this.a = typedArray.getText(2);
        this.b = eVarL.f(0);
        this.c = typedArray.getResourceId(1, 0);
        eVarL.n();
    }
}
