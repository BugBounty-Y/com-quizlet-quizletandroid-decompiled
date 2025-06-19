package com.quizlet.quizletandroid.initializers.app;

import android.app.Activity;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.os.Build;
import com.google.android.gms.internal.mlkit_common.u;
import com.google.android.gms.internal.mlkit_vision_barcode.S6;
import com.quizlet.data.model.C4184z;
import com.quizlet.quizletandroid.R;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes3.dex */
public final class e implements InterfaceC5002j {
    @Override // kotlinx.coroutines.flow.InterfaceC5002j
    public final Object emit(Object obj, kotlin.coroutines.h hVar) throws Resources.NotFoundException {
        Activity activity = (Activity) obj;
        C4184z buildConfigProvider = com.quizlet.quizletandroid.provider.a.a;
        S6.c(buildConfigProvider);
        u isLockScreenRotationAllowed = new u(24);
        Intrinsics.checkNotNullParameter(buildConfigProvider, "buildConfigProvider");
        Intrinsics.checkNotNullParameter(isLockScreenRotationAllowed, "isLockScreenRotationAllowed");
        Intrinsics.checkNotNullParameter(activity, "activity");
        boolean z = activity.getResources().getBoolean(R.bool.isLargeDevice);
        Intrinsics.checkNotNullParameter(activity, "activity");
        boolean z2 = false;
        try {
            Intrinsics.checkNotNullParameter(activity, "<this>");
            TypedArray typedArrayObtainStyledAttributes = activity.getTheme().obtainStyledAttributes(new int[]{android.R.attr.windowIsTranslucent});
            Intrinsics.checkNotNullExpressionValue(typedArrayObtainStyledAttributes, "obtainStyledAttributes(...)");
            boolean z3 = typedArrayObtainStyledAttributes.getBoolean(0, false);
            typedArrayObtainStyledAttributes.recycle();
            z2 = z3;
        } catch (Exception unused) {
        }
        if ((!z2 || Build.VERSION.SDK_INT > 26) && !z) {
            activity.setRequestedOrientation(1);
        }
        return Unit.a;
    }
}
