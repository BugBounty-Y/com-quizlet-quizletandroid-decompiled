package com.quizlet.quizletandroid.ui.setcreation.viewholders;

import android.view.View;
import androidx.recyclerview.widget.F0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a extends F0 {
    public static final /* synthetic */ int c = 0;
    public final com.quizlet.infra.legacysyncengine.tasks.parse.b a;
    public final com.onetrust.otpublishers.headless.databinding.b b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(View itemView, com.quizlet.infra.legacysyncengine.tasks.parse.b selectedLanguageAction) {
        super(itemView);
        Intrinsics.checkNotNullParameter(itemView, "itemView");
        Intrinsics.checkNotNullParameter(selectedLanguageAction, "selectedLanguageAction");
        this.a = selectedLanguageAction;
        com.onetrust.otpublishers.headless.databinding.b bVarB = com.onetrust.otpublishers.headless.databinding.b.b(itemView);
        Intrinsics.checkNotNullExpressionValue(bVarB, "bind(...)");
        this.b = bVarB;
    }
}
