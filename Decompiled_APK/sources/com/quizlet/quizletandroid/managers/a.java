package com.quizlet.quizletandroid.managers;

import android.content.Context;
import android.net.Uri;

/* loaded from: classes3.dex */
public final /* synthetic */ class a implements f {
    public final /* synthetic */ Context a;
    public final /* synthetic */ Uri b;

    public /* synthetic */ a(Context context, Uri uri) {
        this.a = context;
        this.b = uri;
    }

    @Override // com.quizlet.quizletandroid.managers.f
    public final void a(e eVar) {
        if (eVar.equals(e.b)) {
            return;
        }
        com.google.ads.conversiontracking.a.c(this.a, this.b);
    }
}
