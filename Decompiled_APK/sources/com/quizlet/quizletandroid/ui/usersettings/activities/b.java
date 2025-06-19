package com.quizlet.quizletandroid.ui.usersettings.activities;

import android.os.Bundle;
import com.quizlet.quizletandroid.R;

/* loaded from: classes3.dex */
public abstract class b extends com.quizlet.baseui.base.b {
    @Override // com.quizlet.baseui.base.b, androidx.appcompat.app.AbstractActivityC0055k, android.app.Activity
    public final void onPostCreate(Bundle bundle) {
        super.onPostCreate(bundle);
        if (r() != null) {
            r().u(true);
            r().v(com.quizlet.themes.extensions.a.c(this, R.drawable.ic_sys_close_x, android.R.attr.colorControlNormal));
        }
    }

    @Override // com.quizlet.baseui.base.b
    public final int z() {
        return R.layout.activity_fragment_container;
    }
}
