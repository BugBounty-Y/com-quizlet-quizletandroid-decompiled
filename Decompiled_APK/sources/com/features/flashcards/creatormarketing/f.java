package com.features.flashcards.creatormarketing;

import android.content.DialogInterface;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3162h7;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes2.dex */
public final class f extends j {
    public static final String x;
    public boolean v;
    public h w;

    static {
        String simpleName = f.class.getSimpleName();
        Intrinsics.checkNotNullExpressionValue(simpleName, "getSimpleName(...)");
        x = simpleName;
    }

    @Override // androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        return AbstractC3162h7.b(this, new androidx.compose.runtime.internal.d(true, -1629714003, new e(this, 1)));
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, android.content.DialogInterface.OnDismissListener
    public final void onDismiss(DialogInterface dialog) {
        Intrinsics.checkNotNullParameter(dialog, "dialog");
        super.onDismiss(dialog);
        getParentFragmentManager().g0(AbstractC3206m6.a(new Pair("creatorMarketingCreateClicked", Boolean.valueOf(this.v))), "creatorMarketingRequestKey");
    }
}
