package com.google.android.gms.internal.mlkit_vision_common;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.drawable.Drawable;
import com.quizlet.generated.enums.EnumC4503n;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.google.android.gms.internal.mlkit_vision_common.d4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3442d4 {
    public static ColorStateList a(Context context, TypedArray typedArray, int i) {
        int resourceId;
        ColorStateList colorStateListC;
        return (!typedArray.hasValue(i) || (resourceId = typedArray.getResourceId(i, 0)) == 0 || (colorStateListC = androidx.core.content.c.c(context, resourceId)) == null) ? typedArray.getColorStateList(i) : colorStateListC;
    }

    public static ColorStateList b(Context context, com.quizlet.data.repository.classfolder.e eVar, int i) {
        int resourceId;
        ColorStateList colorStateListC;
        TypedArray typedArray = (TypedArray) eVar.c;
        return (!typedArray.hasValue(i) || (resourceId = typedArray.getResourceId(i, 0)) == 0 || (colorStateListC = androidx.core.content.c.c(context, resourceId)) == null) ? eVar.e(i) : colorStateListC;
    }

    public static Drawable c(Context context, TypedArray typedArray, int i) {
        int resourceId;
        Drawable drawableF;
        return (!typedArray.hasValue(i) || (resourceId = typedArray.getResourceId(i, 0)) == 0 || (drawableF = com.facebook.appevents.g.f(context, resourceId)) == null) ? typedArray.getDrawable(i) : drawableF;
    }

    public static final EnumC4503n d(com.quizlet.data.model.m2 m2Var) {
        Intrinsics.checkNotNullParameter(m2Var, "<this>");
        int iOrdinal = m2Var.ordinal();
        if (iOrdinal == 0 || iOrdinal == 1) {
            return EnumC4503n.NOTE_IMPORT_EVENTS;
        }
        if (iOrdinal == 2) {
            return EnumC4503n.PRACTICE_TEST_EVENTS;
        }
        throw new NoWhenBranchMatchedException();
    }

    public static boolean e(Context context) {
        return context.getResources().getConfiguration().fontScale >= 1.3f;
    }
}
