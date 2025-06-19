package com.quizlet.quizletandroid.ui.share;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.quizlet.features.infra.navigation.w;
import com.quizlet.qutils.string.g;
import com.quizlet.utmhelper.b;
import com.quizlet.utmhelper.c;
import com.quizlet.utmhelper.d;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements w {
    public final Context a;
    public final c b;
    public final long c;

    public a(Context context, c utmParamsHelper, long j) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(utmParamsHelper, "utmParamsHelper");
        this.a = context;
        this.b = utmParamsHelper;
        this.c = j;
    }

    @Override // com.quizlet.features.infra.navigation.w
    public final void c(com.quizlet.features.infra.models.share.a request) {
        Intrinsics.checkNotNullParameter(request, "request");
        com.quizlet.utmhelper.a aVar = new com.quizlet.utmhelper.a(Long.valueOf(this.c), request.b, "share-link", "share-sheet-android");
        b bVarA = ((d) this.b).a(aVar);
        String string = Uri.parse(request.a).buildUpon().appendQueryParameter("x", bVarA.b).appendQueryParameter("i", bVarA.a).build().toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        g gVar = (g) request.d.invoke(string);
        Context context = this.a;
        String strA = gVar.a(context);
        Intent intent = new Intent();
        intent.setAction("android.intent.action.SEND");
        intent.putExtra("android.intent.extra.TEXT", strA);
        intent.setType("text/plain");
        context.startActivity(Intent.createChooser(intent, AbstractC3053s1.e(request.c, context)));
        request.e.invoke(new com.quizlet.features.infra.models.share.b(string, aVar));
    }
}
