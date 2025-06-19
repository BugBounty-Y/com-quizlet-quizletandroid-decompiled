package com.quizlet.baserecyclerview;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.recyclerview.widget.V;
import com.onetrust.otpublishers.headless.UI.adapter.s;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class b extends V {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(s diffUtilCallback) {
        super(diffUtilCallback);
        Intrinsics.checkNotNullParameter(diffUtilCallback, "diffUtilCallback");
    }

    public static View g(ViewGroup parent, int i) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        View viewInflate = LayoutInflater.from(parent.getContext()).inflate(i, parent, false);
        Intrinsics.checkNotNullExpressionValue(viewInflate, "inflate(...)");
        return viewInflate;
    }
}
