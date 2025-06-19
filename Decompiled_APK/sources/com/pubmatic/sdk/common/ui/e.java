package com.pubmatic.sdk.common.ui;

import android.view.View;
import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public interface e {
    void onRenderProcessGone();

    void onViewClicked(String str);

    void onViewRendered(@NonNull View view);

    void onViewRenderingFailed(@NonNull com.pubmatic.sdk.common.h hVar);
}
