package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.m4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3673m4 {
    /* JADX WARN: Removed duplicated region for block: B:19:0x003e  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0043  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x005a  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x005f  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x0070  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x0075  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x008a  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x009a  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x009c  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x009f  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x00a3  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x00a5  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x00a9  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x00ab  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x00ae  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x00c6  */
    /* JADX WARN: Removed duplicated region for block: B:67:0x00c8  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x00d4  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x00f3  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x00f5  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x00fe  */
    /* JADX WARN: Removed duplicated region for block: B:79:0x0100  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x0108  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x0113  */
    /* JADX WARN: Removed duplicated region for block: B:91:0x0132  */
    /* JADX WARN: Removed duplicated region for block: B:93:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(com.quizlet.qatex.c r17, androidx.compose.ui.q r18, boolean r19, kotlin.jvm.functions.Function0 r20, kotlin.jvm.functions.Function1 r21, androidx.compose.runtime.InterfaceC0806l r22, int r23, int r24) {
        /*
            Method dump skipped, instructions count: 316
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3673m4.a(com.quizlet.qatex.c, androidx.compose.ui.q, boolean, kotlin.jvm.functions.Function0, kotlin.jvm.functions.Function1, androidx.compose.runtime.l, int, int):void");
    }

    public static final String b(Context context, String str) {
        Intrinsics.checkNotNullParameter(context, "context");
        com.onetrust.otpublishers.headless.Internal.Preferences.e eVar = new com.onetrust.otpublishers.headless.Internal.Preferences.e(context);
        if (!eVar.m() || com.onetrust.otpublishers.headless.Internal.a.j(str)) {
            return str;
        }
        String strO = assistantMode.utils.studiableMetadata.b.o("activeIabVendorsCount", eVar.h());
        Intrinsics.checkNotNullExpressionValue(strO, "otSharedPreferenceUtils.activeVendorCount");
        if (strO.length() == 0) {
            strO = "0";
        }
        if (str != null) {
            return kotlin.text.D.o(str, "[VENDOR_NUMBER]", android.support.v4.media.session.a.B("<b>", strO, "</b>"), false);
        }
        return null;
    }
}
