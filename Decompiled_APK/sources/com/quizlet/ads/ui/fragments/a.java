package com.quizlet.ads.ui.fragments;

import android.content.Context;
import com.google.android.gms.ads.m;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes2.dex */
public final class a {
    public final Context a;

    public a(@NotNull Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = context;
    }

    public final Object a(Object obj) {
        m input = (m) obj;
        Intrinsics.checkNotNullParameter(input, "input");
        com.google.android.gms.ads.nativead.b bVar = new com.google.android.gms.ads.nativead.b(this.a);
        bVar.setMediaContent(input);
        return bVar;
    }
}
