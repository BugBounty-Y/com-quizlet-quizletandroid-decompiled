package com.quizlet.quizletandroid.ui.common.widgets;

import com.quizlet.uicommon.ui.common.widgets.QFormField;

/* loaded from: classes3.dex */
public abstract class e extends QFormField implements dagger.hilt.internal.b {
    public dagger.hilt.android.internal.managers.f x;
    public boolean y;

    @Override // dagger.hilt.internal.b
    public final Object d() {
        if (this.x == null) {
            this.x = new dagger.hilt.android.internal.managers.f(this);
        }
        return this.x.d();
    }
}
