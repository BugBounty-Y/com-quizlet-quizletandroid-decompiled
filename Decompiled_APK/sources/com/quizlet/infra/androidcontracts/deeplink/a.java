package com.quizlet.infra.androidcontracts.deeplink;

import android.content.Context;
import android.content.Intent;
import com.quizlet.quizletandroid.managers.deeplinks.h;

/* loaded from: classes3.dex */
public interface a {
    Intent[] a(Context context);

    boolean b();

    Intent[] c(Context context, h hVar);

    String identity();
}
