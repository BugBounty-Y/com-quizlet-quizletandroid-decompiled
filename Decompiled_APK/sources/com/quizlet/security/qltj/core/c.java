package com.quizlet.security.qltj.core;

import com.quizlet.local.datastore.preferences.J;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlinx.coroutines.internal.d;

/* loaded from: classes3.dex */
public final class c implements com.quizlet.infra.contracts.api.a {
    public final J a;
    public final d b;
    public String c;
    public int d;

    public c(J cookieStoreManager, d ioScope) {
        Intrinsics.checkNotNullParameter(cookieStoreManager, "cookieStoreManager");
        Intrinsics.checkNotNullParameter(ioScope, "ioScope");
        this.a = cookieStoreManager;
        this.b = ioScope;
    }

    public static String a(String str) {
        int iM = StringsKt.M(str, "expires=", 0, false, 6);
        if (iM == -1) {
            return str;
        }
        int iL = StringsKt.L(str, ';', iM, false, 4);
        if (iL == -1) {
            String strSubstring = str.substring(0, iM);
            Intrinsics.checkNotNullExpressionValue(strSubstring, "substring(...)");
            return strSubstring;
        }
        String strSubstring2 = str.substring(0, iM);
        Intrinsics.checkNotNullExpressionValue(strSubstring2, "substring(...)");
        String strSubstring3 = str.substring(iL);
        Intrinsics.checkNotNullExpressionValue(strSubstring3, "substring(...)");
        return android.support.v4.media.session.a.k(strSubstring2, strSubstring3);
    }
}
