package com.quizlet.diagrams.ui;

import android.webkit.JavascriptInterface;
import androidx.annotation.Keep;
import com.quizlet.diagrams.DiagramWebView;
import com.quizlet.features.folders.composables.J;
import java.util.Arrays;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class DiagramJSBridge {
    public final C a;
    public DiagramWebView b;
    public J c;

    public DiagramJSBridge(C scope) {
        Intrinsics.checkNotNullParameter(scope, "scope");
        this.a = scope;
    }

    public final void a(long j) {
        String str = String.format("onCorrectTerm('%d');", Arrays.copyOf(new Object[]{Long.valueOf(j)}, 1));
        Intrinsics.checkNotNullExpressionValue(str, "format(...)");
        executeJs$diagrams_release(str);
    }

    public final void b(long j) {
        String str = String.format("onIncorrectTerm('%d');", Arrays.copyOf(new Object[]{Long.valueOf(j)}, 1));
        Intrinsics.checkNotNullExpressionValue(str, "format(...)");
        executeJs$diagrams_release(str);
    }

    @JavascriptInterface
    public final void executeJs$diagrams_release(@NotNull String js) {
        Intrinsics.checkNotNullParameter(js, "js");
        DiagramWebView diagramWebView = this.b;
        if (diagramWebView == null) {
            Intrinsics.m("webView");
            throw null;
        }
        diagramWebView.loadUrl("javascript:" + js);
    }

    @JavascriptInterface
    @Keep
    public final void onTermClick(@NotNull String termId, boolean z) {
        Intrinsics.checkNotNullParameter(termId, "termId");
        E.A(this.a, null, null, new c(this, termId, z, null), 3);
    }
}
