package com.google.android.gms.internal.mlkit_vision_camera;

import android.view.View;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3315z6;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.Locale;
import java.util.regex.Matcher;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_camera.h2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3347h2 {
    /* JADX WARN: Removed duplicated region for block: B:100:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:23:0x0042  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0057  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x005d  */
    /* JADX WARN: Removed duplicated region for block: B:42:0x0072  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x0078  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x007d  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x0096  */
    /* JADX WARN: Removed duplicated region for block: B:57:0x0098  */
    /* JADX WARN: Removed duplicated region for block: B:66:0x00b1  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x00c1  */
    /* JADX WARN: Removed duplicated region for block: B:82:0x00e5  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x00e7  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x00ea  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x00ef  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x0100  */
    /* JADX WARN: Removed duplicated region for block: B:91:0x0105  */
    /* JADX WARN: Removed duplicated region for block: B:93:0x0118  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x0163  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(java.lang.String r17, androidx.compose.ui.q r18, long r19, long r21, java.lang.String r23, androidx.compose.runtime.InterfaceC0806l r24, int r25, int r26) {
        /*
            Method dump skipped, instructions count: 368
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_camera.AbstractC3347h2.a(java.lang.String, androidx.compose.ui.q, long, long, java.lang.String, androidx.compose.runtime.l, int, int):void");
    }

    public static final androidx.savedstate.f b(View view) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        while (view != null) {
            Object tag = view.getTag(R.id.view_tree_saved_state_registry_owner);
            androidx.savedstate.f fVar = tag instanceof androidx.savedstate.f ? (androidx.savedstate.f) tag : null;
            if (fVar != null) {
                return fVar;
            }
            Object objB = AbstractC3315z6.b(view);
            view = objB instanceof View ? (View) objB : null;
        }
        return null;
    }

    public static okhttp3.w c(String str) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        Matcher matcher = okhttp3.w.e.matcher(str);
        if (!matcher.lookingAt()) {
            throw new IllegalArgumentException(androidx.compose.ui.node.B.h("No subtype found for: \"", str, '\"').toString());
        }
        String strGroup = matcher.group(1);
        Intrinsics.checkNotNullExpressionValue(strGroup, "typeSubtype.group(1)");
        Locale US = Locale.US;
        String strK = androidx.compose.ui.node.B.k(US, "US", strGroup, US, "this as java.lang.String).toLowerCase(locale)");
        String strGroup2 = matcher.group(2);
        Intrinsics.checkNotNullExpressionValue(strGroup2, "typeSubtype.group(2)");
        Intrinsics.checkNotNullExpressionValue(US, "US");
        String lowerCase = strGroup2.toLowerCase(US);
        Intrinsics.checkNotNullExpressionValue(lowerCase, "this as java.lang.String).toLowerCase(locale)");
        ArrayList arrayList = new ArrayList();
        Matcher matcher2 = okhttp3.w.f.matcher(str);
        int iEnd = matcher.end();
        while (iEnd < str.length()) {
            matcher2.region(iEnd, str.length());
            if (!matcher2.lookingAt()) {
                StringBuilder sb = new StringBuilder("Parameter is not formatted correctly: \"");
                String strSubstring = str.substring(iEnd);
                Intrinsics.checkNotNullExpressionValue(strSubstring, "this as java.lang.String).substring(startIndex)");
                sb.append(strSubstring);
                sb.append("\" for: \"");
                throw new IllegalArgumentException(androidx.compose.animation.d0.r(sb, str, '\"').toString());
            }
            String strGroup3 = matcher2.group(1);
            if (strGroup3 == null) {
                iEnd = matcher2.end();
            } else {
                String strGroup4 = matcher2.group(2);
                if (strGroup4 == null) {
                    strGroup4 = matcher2.group(3);
                } else if (kotlin.text.D.r(strGroup4, "'", false) && kotlin.text.D.k(strGroup4, "'", false) && strGroup4.length() > 2) {
                    strGroup4 = strGroup4.substring(1, strGroup4.length() - 1);
                    Intrinsics.checkNotNullExpressionValue(strGroup4, "this as java.lang.String…ing(startIndex, endIndex)");
                }
                arrayList.add(strGroup3);
                arrayList.add(strGroup4);
                iEnd = matcher2.end();
            }
        }
        return new okhttp3.w(str, strK, lowerCase, (String[]) arrayList.toArray(new String[0]));
    }

    public static okhttp3.w d(String str) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        try {
            return c(str);
        } catch (IllegalArgumentException unused) {
            return null;
        }
    }

    public static final void e(View view, androidx.savedstate.f fVar) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        view.setTag(R.id.view_tree_saved_state_registry_owner, fVar);
    }
}
