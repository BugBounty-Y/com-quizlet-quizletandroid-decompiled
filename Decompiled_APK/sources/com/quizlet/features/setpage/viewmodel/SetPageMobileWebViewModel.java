package com.quizlet.features.setpage.viewmodel;

import android.webkit.JavascriptInterface;
import androidx.annotation.Keep;
import androidx.lifecycle.w0;
import kotlin.Metadata;
import kotlin.text.StringsKt;

@Metadata
/* loaded from: classes3.dex */
public final class SetPageMobileWebViewModel extends w0 {

    @Metadata
    public final class JsBridge {
        @JavascriptInterface
        @Keep
        public final void onCloseMcqSetWebview(String str) {
            if (str != null) {
                StringsKt.G(str, "in_progress", false);
            }
            throw null;
        }
    }
}
