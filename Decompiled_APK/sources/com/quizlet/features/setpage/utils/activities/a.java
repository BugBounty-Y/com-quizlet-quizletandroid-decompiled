package com.quizlet.features.setpage.utils.activities;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import com.quizlet.quizletandroid.ui.webpages.WebViewActivity;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class a {
    public static final /* synthetic */ int a = 0;

    public static Intent a(Context context, String str, String str2) {
        Intent intent = new Intent(context, (Class<?>) WebViewActivity.class);
        intent.putExtra("extra.url", str);
        intent.putExtra("extra.mTitle", str2);
        Bundle EMPTY = Bundle.EMPTY;
        Intrinsics.checkNotNullExpressionValue(EMPTY, "EMPTY");
        intent.putExtra("extra.request.params", EMPTY);
        return intent;
    }
}
