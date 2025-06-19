package com.google.android.gms.internal.mlkit_vision_barcode;

import android.R;
import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import io.ktor.http.AbstractC4879a;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_barcode.e7, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3135e7 {
    /* JADX WARN: Removed duplicated region for block: B:28:0x0058  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x0075  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x0077  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x007c  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00d4  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x00d8  */
    /* JADX WARN: Removed duplicated region for block: B:50:0x00f9  */
    /* JADX WARN: Removed duplicated region for block: B:54:0x0189  */
    /* JADX WARN: Removed duplicated region for block: B:56:? A[RETURN, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final void a(int r25, int r26, androidx.compose.runtime.InterfaceC0806l r27, androidx.compose.ui.q r28, java.lang.String r29, kotlin.jvm.functions.Function0 r30) {
        /*
            Method dump skipped, instructions count: 407
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3135e7.a(int, int, androidx.compose.runtime.l, androidx.compose.ui.q, java.lang.String, kotlin.jvm.functions.Function0):void");
    }

    public static final io.ktor.http.s b(io.ktor.http.t parameters) {
        Intrinsics.checkNotNullParameter(parameters, "parameters");
        io.ktor.http.u uVar = new io.ktor.http.u(13);
        for (String str : parameters.names()) {
            List listH = parameters.h(str);
            if (listH == null) {
                listH = kotlin.collections.K.a;
            }
            String strD = AbstractC4879a.d(0, 0, str, 15);
            ArrayList arrayList = new ArrayList(kotlin.collections.C.q(listH, 10));
            Iterator it2 = listH.iterator();
            while (it2.hasNext()) {
                arrayList.add(AbstractC4879a.d(0, 0, (String) it2.next(), 11));
            }
            uVar.e(strD, arrayList);
        }
        Map values = (Map) uVar.b;
        Intrinsics.checkNotNullParameter(values, "values");
        return new io.ktor.http.v(values);
    }

    public static int c(Context context, int i) throws Resources.NotFoundException {
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(R.style.Animation.Activity, new int[]{i});
        int resourceId = typedArrayObtainStyledAttributes.getResourceId(0, -1);
        typedArrayObtainStyledAttributes.recycle();
        return resourceId;
    }
}
