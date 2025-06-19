package com.quizlet.quizletandroid.managers.deeplinks;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ResolveInfo;
import android.net.Uri;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3508o4;
import java.util.Iterator;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.managers.deeplinks.d, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4630d implements com.quizlet.infra.androidcontracts.deeplink.a {
    public static final String b;
    public final Uri a;

    static {
        String simpleName = C4630d.class.getSimpleName();
        Intrinsics.checkNotNullExpressionValue(simpleName, "getSimpleName(...)");
        b = simpleName;
    }

    public C4630d(Uri uri) {
        Intrinsics.checkNotNullParameter(uri, "uri");
        this.a = uri;
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final Intent[] a(Context context) {
        Uri uri;
        String str;
        Intrinsics.checkNotNullParameter(context, "context");
        Intent intent = new Intent("android.intent.action.VIEW", Uri.parse("https://nonexistentsubdomain.quizlet.com/"));
        intent.addCategory("android.intent.category.BROWSABLE");
        List<ResolveInfo> listQueryIntentActivities = context.getPackageManager().queryIntentActivities(intent, 0);
        Intrinsics.checkNotNullExpressionValue(listQueryIntentActivities, "queryIntentActivities(...)");
        String packageName = context.getPackageName();
        Iterator<T> it2 = listQueryIntentActivities.iterator();
        do {
            boolean zHasNext = it2.hasNext();
            uri = this.a;
            if (!zHasNext) {
                timber.log.c.a.o("Unable to find package to handle uri: %s", uri);
                return new Intent[]{intent.setData(uri)};
            }
            str = ((ResolveInfo) it2.next()).activityInfo.packageName;
        } while (Intrinsics.b(packageName, str));
        Intent intent2 = new Intent("android.intent.action.VIEW", uri);
        intent.addCategory("android.intent.category.BROWSABLE");
        intent2.setPackage(str);
        return new Intent[]{intent2};
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final boolean b() {
        return true;
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final Intent[] c(Context context, h hVar) {
        return AbstractC3508o4.b(this, context, hVar);
    }

    @Override // com.quizlet.infra.androidcontracts.deeplink.a
    public final String identity() {
        return b;
    }

    public final String toString() {
        return "BrowserDeepLink(" + this.a + ")";
    }
}
