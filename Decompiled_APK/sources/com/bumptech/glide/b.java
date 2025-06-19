package com.bumptech.glide;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ResolveInfo;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public abstract class b {
    public static final /* synthetic */ int a = 0;

    public static ResolveInfo a(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        return context.getPackageManager().resolveActivity(new Intent("androidx.activity.result.contract.action.PICK_IMAGES"), 1114112);
    }

    public static String b(androidx.activity.result.contract.g input) {
        Intrinsics.checkNotNullParameter(input, "input");
        if (input instanceof androidx.activity.result.contract.f) {
            return "image/*";
        }
        if (input instanceof androidx.activity.result.contract.e) {
            return null;
        }
        throw new NoWhenBranchMatchedException();
    }

    public static final boolean c(int i) {
        return i == 1 || i == 4;
    }
}
