package com.google.android.gms.internal.mlkit_vision_common;

import android.view.View;
import android.view.ViewGroup;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.z2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3570z2 {
    public static final /* synthetic */ int a = 0;

    /* JADX WARN: Code restructure failed: missing block: B:71:0x0174, code lost:
    
        if (kotlin.jvm.internal.Intrinsics.b(r1, r10) == false) goto L81;
     */
    /* JADX WARN: Removed duplicated region for block: B:32:0x00d0  */
    /* JADX WARN: Removed duplicated region for block: B:37:0x00e0  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x0100  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x012e  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x014d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.util.ArrayList a(android.view.View r7, java.util.List r8, int r9, int r10, java.lang.String r11) {
        /*
            Method dump skipped, instructions count: 426
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_common.AbstractC3570z2.a(android.view.View, java.util.List, int, int, java.lang.String):java.util.ArrayList");
    }

    public static ArrayList b(ViewGroup viewGroup) {
        ArrayList arrayList = new ArrayList();
        int childCount = viewGroup.getChildCount();
        for (int i = 0; i < childCount; i++) {
            View child = viewGroup.getChildAt(i);
            if (child.getVisibility() == 0) {
                Intrinsics.checkNotNullExpressionValue(child, "child");
                arrayList.add(child);
            }
        }
        return arrayList;
    }
}
