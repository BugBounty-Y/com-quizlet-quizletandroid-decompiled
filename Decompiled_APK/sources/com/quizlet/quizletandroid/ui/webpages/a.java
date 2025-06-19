package com.quizlet.quizletandroid.ui.webpages;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.widget.Toast;
import com.quizlet.quizletandroid.R;
import com.quizlet.ui.models.webpage.m;
import java.util.List;
import kotlin.collections.A;
import kotlin.collections.B;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import timber.log.c;

/* loaded from: classes3.dex */
public final class a {
    public static final a a = new a();
    public static final List b = B.j("quizlet.com", "www.quizlet.com", "help.quizlet.com");
    public static final List c = A.b("docs.google.com");

    public static final boolean d(Uri uri) {
        Intrinsics.checkNotNullParameter(uri, "uri");
        return b.contains(uri.getHost()) || c.contains(uri.getHost()) || CollectionsKt.F(com.quizlet.generated.deeplinkpaths.a.c, uri.getHost());
    }

    public final boolean a(Context context, Uri uri) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(uri, "uri");
        Intent intent = new Intent("android.intent.action.VIEW", uri);
        if (context.getPackageManager().resolveActivity(intent, 0) != null) {
            context.startActivity(intent);
            return true;
        }
        Toast.makeText(context, R.string.web_browser_disabled_error, 1).show();
        c.a.d("All web browsers are disabled!", new Object[0]);
        return false;
    }

    /* JADX WARN: Removed duplicated region for block: B:55:0x0145  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x0148 A[EDGE_INSN: B:88:0x0148->B:56:0x0148 BREAK  A[LOOP:1: B:38:0x0112->B:89:0x0112]] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void b(android.content.Context r13, java.lang.String r14, java.lang.String r15) {
        /*
            Method dump skipped, instructions count: 394
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.webpages.a.b(android.content.Context, java.lang.String, java.lang.String):void");
    }

    public final void c(Context context, m webPage) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(webPage, "webPage");
        b(context, webPage.b(), webPage.a().a(context));
    }
}
