package com.skydoves.balloon;

import android.view.View;
import androidx.activity.s;
import androidx.fragment.app.Fragment;
import com.skydoves.balloon.Balloon;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.k;

@Metadata
/* loaded from: classes3.dex */
public final class BalloonLazyExtensionKt {
    @BalloonInlineDsl
    public static final <T extends Balloon.Factory> k balloon(androidx.viewbinding.a aVar) {
        Intrinsics.checkNotNullParameter(aVar, "<this>");
        Intrinsics.checkNotNullExpressionValue(aVar.getRoot(), "getRoot(...)");
        throw new UnsupportedOperationException("This function has a reified type parameter and thus can only be inlined at compilation time, not called directly.");
    }

    @BalloonInlineDsl
    public static final <T extends Balloon.Factory> k balloon(View view) {
        Intrinsics.checkNotNullParameter(view, "<this>");
        throw new UnsupportedOperationException("This function has a reified type parameter and thus can only be inlined at compilation time, not called directly.");
    }

    @BalloonInlineDsl
    public static final <T extends Balloon.Factory> k balloon(s sVar) {
        Intrinsics.checkNotNullParameter(sVar, "<this>");
        throw new UnsupportedOperationException("This function has a reified type parameter and thus can only be inlined at compilation time, not called directly.");
    }

    @BalloonInlineDsl
    public static final <T extends Balloon.Factory> k balloon(Fragment fragment) {
        Intrinsics.checkNotNullParameter(fragment, "<this>");
        throw new UnsupportedOperationException("This function has a reified type parameter and thus can only be inlined at compilation time, not called directly.");
    }
}
