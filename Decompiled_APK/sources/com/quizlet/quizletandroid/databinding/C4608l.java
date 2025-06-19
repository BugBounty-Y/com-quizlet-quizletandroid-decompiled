package com.quizlet.quizletandroid.databinding;

import android.view.View;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import com.quizlet.quizletandroid.ui.studymodes.write.WriteModeCheckPointView;
import com.quizlet.quizletandroid.ui.studymodes.write.WriteModePromptView;
import com.quizlet.quizletandroid.ui.studymodes.write.WriteModeResultsView;

/* renamed from: com.quizlet.quizletandroid.databinding.l, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4608l implements androidx.viewbinding.a {
    public final LinearLayout a;
    public final FrameLayout b;
    public final WriteModeCheckPointView c;
    public final WriteModePromptView d;
    public final WriteModeResultsView e;
    public final com.quizlet.features.infra.legacyadapter.databinding.f f;
    public final com.onetrust.otpublishers.headless.databinding.b g;

    public C4608l(LinearLayout linearLayout, FrameLayout frameLayout, WriteModeCheckPointView writeModeCheckPointView, WriteModePromptView writeModePromptView, WriteModeResultsView writeModeResultsView, com.quizlet.features.infra.legacyadapter.databinding.f fVar, com.onetrust.otpublishers.headless.databinding.b bVar) {
        this.a = linearLayout;
        this.b = frameLayout;
        this.c = writeModeCheckPointView;
        this.d = writeModePromptView;
        this.e = writeModeResultsView;
        this.f = fVar;
        this.g = bVar;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
