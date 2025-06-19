package com.quizlet.uicommon.ui.common.overflowmenu;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.F0;
import androidx.recyclerview.widget.V;
import com.onetrust.otpublishers.headless.UI.adapter.s;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a extends V {
    public final com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.a c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.a clickCallback) {
        super(new s(6));
        Intrinsics.checkNotNullParameter(clickCallback, "clickCallback");
        this.c = clickCallback;
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final void onBindViewHolder(F0 f0, int i) {
        e holder = (e) f0;
        Intrinsics.checkNotNullParameter(holder, "holder");
        Object objD = d(i);
        Intrinsics.checkNotNullExpressionValue(objD, "getItem(...)");
        holder.c((f) objD);
    }

    @Override // androidx.recyclerview.widget.AbstractC1361d0
    public final F0 onCreateViewHolder(ViewGroup parent, int i) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        View viewInflate = LayoutInflater.from(parent.getContext()).inflate(R.layout.view_fullscreen_overflow_item, parent, false);
        Intrinsics.d(viewInflate);
        return new e(viewInflate, this.c);
    }
}
