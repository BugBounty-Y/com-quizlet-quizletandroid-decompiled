package com.quizlet.quizletandroid.ui.diagramming;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Parcel;
import android.os.Parcelable;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.webkit.JavascriptInterface;
import android.webkit.WebView;
import android.widget.FrameLayout;
import androidx.annotation.Keep;
import com.facebook.internal.L;
import com.google.android.gms.internal.mlkit_vision_barcode.K6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.diagrams.DiagramWebView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.u;
import com.quizlet.studiablemodels.diagrams.DiagramData;
import io.reactivex.rxjava3.internal.operators.observable.C4887f;
import io.reactivex.rxjava3.subjects.s;
import java.io.IOException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashSet;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.collections.U;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
@SuppressLint({"AddJavascriptInterface", "SetJavaScriptEnabled"})
/* loaded from: classes3.dex */
public final class DiagramView extends FrameLayout {
    public final com.onetrust.otpublishers.headless.databinding.b a;
    public j b;
    public final io.reactivex.rxjava3.subjects.j c;
    public com.quizlet.features.infra.legacyadapter.h d;
    public boolean e;
    public final C4887f f;

    @Metadata
    public static final class SavedState extends View.BaseSavedState {

        @NotNull
        public static final k CREATOR = new k();
        public long[] a;

        @Override // android.view.View.BaseSavedState, android.view.AbsSavedState, android.os.Parcelable
        public final void writeToParcel(Parcel out, int i) {
            Intrinsics.checkNotNullParameter(out, "out");
            super.writeToParcel(out, i);
            out.writeLongArray(this.a);
        }
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public DiagramView(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    public static void a(DiagramView diagramView, DiagramData diagramData, com.quizlet.diagrams.b[] bVarArr, io.reactivex.rxjava3.internal.operators.completable.d emitter) {
        Intrinsics.checkNotNullParameter(emitter, "emitter");
        diagramView.getWebView().setWebViewClient(new L(emitter, 5));
        diagramView.d(diagramData, (com.quizlet.diagrams.b[]) Arrays.copyOf(bVarArr, bVarArr.length));
    }

    private final View getInvisibleButton() {
        View invisibleButton = this.a.c;
        Intrinsics.checkNotNullExpressionValue(invisibleButton, "invisibleButton");
        return invisibleButton;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final WebView getWebView() {
        DiagramWebView webView = (DiagramWebView) this.a.d;
        Intrinsics.checkNotNullExpressionValue(webView, "webView");
        return webView;
    }

    public final void c(String str) {
        getWebView().loadDataWithBaseURL("file:///android_asset/", str, "text/html", "utf-8", null);
    }

    public final void d(DiagramData diagramData, com.quizlet.diagrams.b... diagramLoadingConfigurations) throws IOException {
        Intrinsics.checkNotNullParameter(diagramData, "data");
        Intrinsics.checkNotNullParameter(diagramLoadingConfigurations, "diagramLoadingConfigurations");
        j presenter = getPresenter();
        com.quizlet.diagrams.b[] diagramLoadingConfigurations2 = (com.quizlet.diagrams.b[]) Arrays.copyOf(diagramLoadingConfigurations, diagramLoadingConfigurations.length);
        presenter.getClass();
        Intrinsics.checkNotNullParameter(diagramData, "data");
        Intrinsics.checkNotNullParameter(diagramLoadingConfigurations2, "diagramLoadingConfigurations");
        StringBuilder sb = new StringBuilder();
        sb.append("init(%s);");
        Intrinsics.checkNotNullExpressionValue(sb, "append(...)");
        com.quizlet.diagrams.b[] bVarArr = (com.quizlet.diagrams.b[]) Arrays.copyOf(diagramLoadingConfigurations2, diagramLoadingConfigurations2.length);
        for (com.quizlet.diagrams.b bVar : bVarArr) {
            sb.append(bVar.a);
        }
        if (!C4933y.u(com.quizlet.diagrams.b.c, bVarArr)) {
            sb.append("showTerms();");
        }
        sb.append("renderDiagram();");
        Intrinsics.checkNotNullParameter(diagramData, "diagramData");
        String strWriteValueAsString = presenter.b.writeValueAsString(diagramData);
        Intrinsics.checkNotNullExpressionValue(strWriteValueAsString, "writeValueAsString(...)");
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        DiagramView diagramView = presenter.f;
        if (diagramView == null) {
            Intrinsics.m("view");
            throw null;
        }
        final io.reactivex.rxjava3.subjects.j jVar = presenter.c;
        final io.reactivex.rxjava3.subjects.j jVar2 = presenter.d;
        Object obj = new Object(jVar, jVar2) { // from class: com.quizlet.quizletandroid.ui.diagramming.DiagramPresenter$JsInterface
            public final s a;
            public final s b;

            {
                Intrinsics.checkNotNullParameter(jVar, "termClickObserver");
                Intrinsics.checkNotNullParameter(jVar2, "clickObserver");
                this.a = jVar;
                this.b = jVar2;
            }

            @JavascriptInterface
            @Keep
            public final void onClick() {
                this.b.b(Unit.a);
            }

            @JavascriptInterface
            @Keep
            public final void onTermClick(@NotNull String termId, boolean z) {
                Intrinsics.checkNotNullParameter(termId, "termId");
                this.a.b(new com.quizlet.diagrams.f(Long.parseLong(termId), z));
            }
        };
        Intrinsics.checkNotNullParameter(obj, "obj");
        Intrinsics.checkNotNullParameter("_diagram", "namespace");
        diagramView.getWebView().getSettings().setJavaScriptEnabled(true);
        diagramView.getWebView().getSettings().setAllowFileAccessFromFileURLs(true);
        diagramView.getWebView().addJavascriptInterface(obj, "_diagram");
        String strB = com.fasterxml.uuid.b.b(presenter.a.getAssets().open("diagrams/diagram.html"));
        Intrinsics.checkNotNullExpressionValue(strB, "readInputStream(...)");
        StringBuilder sb2 = new StringBuilder();
        String str = String.format(string, Arrays.copyOf(new Object[]{strWriteValueAsString}, 1));
        Intrinsics.checkNotNullExpressionValue(str, "format(...)");
        sb2.append(str);
        Intrinsics.checkNotNullExpressionValue(sb2, "append(...)");
        Iterator it2 = presenter.e.iterator();
        while (it2.hasNext()) {
            String str2 = String.format("onSelectTerm('%d');", Arrays.copyOf(new Object[]{Long.valueOf(((Number) it2.next()).longValue())}, 1));
            Intrinsics.checkNotNullExpressionValue(str2, "format(...)");
            sb2.append(str2);
        }
        DiagramView diagramView2 = presenter.f;
        if (diagramView2 == null) {
            Intrinsics.m("view");
            throw null;
        }
        String html = String.format(strB, Arrays.copyOf(new Object[]{sb2.toString()}, 1));
        Intrinsics.checkNotNullExpressionValue(html, "format(...)");
        Intrinsics.checkNotNullParameter(html, "html");
        com.quizlet.features.infra.legacyadapter.h hVar = diagramView2.d;
        if (hVar != null) {
            diagramView2.getWebView().getViewTreeObserver().removeOnGlobalLayoutListener(hVar);
            diagramView2.d = null;
        }
        if (diagramView2.getWebView().getHeight() > 0) {
            diagramView2.c(html);
        } else {
            diagramView2.d = new com.quizlet.features.infra.legacyadapter.h(diagramView2, html);
            diagramView2.getWebView().getViewTreeObserver().addOnGlobalLayoutListener(diagramView2.d);
        }
    }

    public final void e(String url) {
        Intrinsics.checkNotNullParameter(url, "url");
        getWebView().loadUrl(url);
    }

    public final void f() {
        this.e = false;
        getInvisibleButton().setVisibility(0);
        getInvisibleButton().setOnClickListener(new com.quizlet.quizletandroid.ui.common.adapter.viewholder.h(this, 3));
    }

    @NotNull
    public io.reactivex.rxjava3.core.i getClicks() {
        if (this.e) {
            io.reactivex.rxjava3.subjects.j jVar = getPresenter().d;
            jVar.getClass();
            C4887f c4887f = new C4887f(jVar, 2);
            Intrinsics.checkNotNullExpressionValue(c4887f, "hide(...)");
            return c4887f;
        }
        io.reactivex.rxjava3.subjects.j jVar2 = this.c;
        jVar2.getClass();
        C4887f c4887f2 = new C4887f(jVar2, 2);
        Intrinsics.checkNotNullExpressionValue(c4887f2, "hide(...)");
        return c4887f2;
    }

    @NotNull
    public final j getPresenter() {
        j jVar = this.b;
        if (jVar != null) {
            return jVar;
        }
        Intrinsics.m("presenter");
        throw null;
    }

    @NotNull
    public io.reactivex.rxjava3.core.i getTermClicks() {
        return this.f;
    }

    @Override // android.view.View
    public final void onRestoreInstanceState(Parcelable parcelable) {
        if (!(parcelable instanceof SavedState)) {
            super.onRestoreInstanceState(parcelable);
            return;
        }
        SavedState savedState = (SavedState) parcelable;
        super.onRestoreInstanceState(savedState.getSuperState());
        j presenter = getPresenter();
        long[] jArr = savedState.a;
        Intrinsics.checkNotNullParameter(jArr, "<this>");
        LinkedHashSet destination = new LinkedHashSet(U.a(jArr.length));
        Intrinsics.checkNotNullParameter(jArr, "<this>");
        Intrinsics.checkNotNullParameter(destination, "destination");
        for (long j : jArr) {
            destination.add(Long.valueOf(j));
        }
        presenter.getClass();
        Intrinsics.checkNotNullParameter(destination, "<set-?>");
        presenter.e = destination;
    }

    @Override // android.view.View
    public final Parcelable onSaveInstanceState() {
        SavedState savedState = new SavedState(super.onSaveInstanceState());
        savedState.a = new long[0];
        long[] jArrX0 = CollectionsKt.x0(getPresenter().e);
        Intrinsics.checkNotNullParameter(jArrX0, "<set-?>");
        savedState.a = jArrX0;
        return savedState;
    }

    public final void setPresenter(@NotNull j jVar) {
        Intrinsics.checkNotNullParameter(jVar, "<set-?>");
        this.b = jVar;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public DiagramView(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public DiagramView(Context context, AttributeSet attributeSet, int i) {
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet, 0);
        LayoutInflater.from(context).inflate(R.layout.diagram_view, this);
        int i2 = R.id.invisibleButton;
        View viewC = AbstractC3375o2.c(R.id.invisibleButton, this);
        if (viewC != null) {
            i2 = R.id.webView;
            DiagramWebView diagramWebView = (DiagramWebView) AbstractC3375o2.c(R.id.webView, this);
            if (diagramWebView != null) {
                com.onetrust.otpublishers.headless.databinding.b bVar = new com.onetrust.otpublishers.headless.databinding.b(this, viewC, diagramWebView, 1);
                Intrinsics.checkNotNullExpressionValue(bVar, "inflate(...)");
                this.a = bVar;
                io.reactivex.rxjava3.subjects.j jVar = new io.reactivex.rxjava3.subjects.j();
                Intrinsics.checkNotNullExpressionValue(jVar, "create(...)");
                this.c = jVar;
                u uVar = (u) ((com.quizlet.quizletandroid.injection.components.a) K6.b(com.quizlet.quizletandroid.injection.components.a.class, context.getApplicationContext()));
                this.b = new j(uVar.q(), uVar.f());
                j presenter = getPresenter();
                presenter.getClass();
                Intrinsics.checkNotNullParameter(this, "view");
                presenter.f = this;
                this.e = true;
                io.reactivex.rxjava3.subjects.j jVar2 = getPresenter().c;
                jVar2.getClass();
                C4887f c4887f = new C4887f(jVar2, 2);
                Intrinsics.checkNotNullExpressionValue(c4887f, "hide(...)");
                this.f = c4887f;
                return;
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(getResources().getResourceName(i2)));
    }
}
