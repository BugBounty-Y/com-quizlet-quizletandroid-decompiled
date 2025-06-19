package com.perimeterx.mobile_sdk.block;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.webkit.WebSettings;
import android.webkit.WebView;
import androidx.appcompat.app.AbstractActivityC0055k;
import androidx.camera.camera2.internal.RunnableC0142t;
import com.perimeterx.mobile_sdk.PerimeterX;
import com.perimeterx.mobile_sdk.configurations.h;
import com.perimeterx.mobile_sdk.configurations.i;
import com.perimeterx.mobile_sdk.session.n;
import com.perimeterx.mobile_sdk.web_view_interception.PXJavaScriptInterface;
import com.perimeterx.mobile_sdk.web_view_interception.f;
import com.quizlet.quizletandroid.R;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlinx.coroutines.E;
import kotlinx.coroutines.O;

@Metadata
/* loaded from: classes2.dex */
public final class PXBlockActivity extends AbstractActivityC0055k implements f {
    public static final HashMap e = new HashMap();
    public String c;
    public String d;

    @Override // com.perimeterx.mobile_sdk.web_view_interception.f
    public final void a(com.google.android.material.floatingactionbutton.c challengeEvent) {
        String str;
        a aVar;
        Intrinsics.checkNotNullParameter(challengeEvent, "challengeEvent");
        com.perimeterx.mobile_sdk.web_view_interception.c cVar = (com.perimeterx.mobile_sdk.web_view_interception.c) challengeEvent.b;
        com.perimeterx.mobile_sdk.web_view_interception.c cVar2 = com.perimeterx.mobile_sdk.web_view_interception.c.c;
        if ((cVar != cVar2 && cVar != com.perimeterx.mobile_sdk.web_view_interception.c.d) || (str = this.c) == null || (aVar = (a) e.get(str)) == null) {
            return;
        }
        boolean z = cVar == cVar2;
        Intrinsics.checkNotNullParameter(this, "activity");
        com.perimeterx.mobile_sdk.session.d dVar = aVar.a;
        if (dVar != null) {
            new Handler(Looper.getMainLooper()).post(new RunnableC0142t(z, dVar));
        }
    }

    @Override // androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        com.perimeterx.mobile_sdk.doctor_app.model.b bVar;
        super.onCreate(bundle);
        if (getResources().getConfiguration().orientation == 1) {
            setRequestedOrientation(1);
        } else if (getResources().getConfiguration().orientation == 2) {
            setRequestedOrientation(0);
        }
        setContentView(R.layout.activity_px_block);
        com.bumptech.glide.c cVarR = r();
        if (cVarR != null) {
            cVarR.k();
        }
        this.c = getIntent().getStringExtra("uuid");
        this.d = getIntent().getStringExtra("vid");
        String page = getIntent().getStringExtra("page");
        Intrinsics.d(page);
        WebView webView = (WebView) findViewById(R.id.block_web_view);
        webView.setVerticalScrollBarEnabled(true);
        webView.setHorizontalScrollBarEnabled(true);
        e eVar = new e();
        eVar.a = this;
        eVar.b = this;
        webView.setWebViewClient(eVar);
        WebSettings settings = webView.getSettings();
        StringBuilder sb = new StringBuilder();
        sb.append(webView.getSettings().getUserAgentString());
        sb.append(' ');
        PerimeterX perimeterX = PerimeterX.INSTANCE;
        Intrinsics.checkNotNullParameter(perimeterX, "<this>");
        sb.append(h.e.a() + perimeterX.sdkVersion());
        settings.setUserAgentString(sb.toString());
        webView.getSettings().setJavaScriptEnabled(true);
        webView.getSettings().setDomStorageEnabled(true);
        PXJavaScriptInterface pXJavaScriptInterface = new PXJavaScriptInterface();
        pXJavaScriptInterface.get_internal$PerimeterX_release().a = this;
        webView.addJavascriptInterface(pXJavaScriptInterface, "pxCaptcha");
        webView.loadDataWithBaseURL("https://perimeterx.net", page, "text/html", i.a, "");
        androidx.constraintlayout.core.widgets.analyzer.f fVar = androidx.constraintlayout.core.widgets.analyzer.f.j;
        if (fVar != null) {
            Intrinsics.checkNotNullParameter(page, "page");
            if (fVar.f() && StringsKt.G(page, "m=1", false) && (bVar = ((com.perimeterx.mobile_sdk.doctor_app.model.d) fVar.i).e) != null) {
                bVar.c = true;
            }
        }
    }

    @Override // androidx.appcompat.app.AbstractActivityC0055k, androidx.fragment.app.I, android.app.Activity
    public final void onDestroy() {
        a aVar = (a) e.get(this.c);
        if (aVar != null) {
            aVar.a(this);
        }
        super.onDestroy();
    }

    @Override // androidx.fragment.app.I, android.app.Activity
    public final void onPause() {
        a aVar = (a) e.get(this.c);
        if (aVar != null) {
            aVar.a(this);
        }
        super.onPause();
    }

    public final void x(com.perimeterx.mobile_sdk.models.d cookie) {
        com.perimeterx.mobile_sdk.models.f token;
        com.perimeterx.mobile_sdk.doctor_app.model.b bVar;
        String str = this.c;
        if (str != null) {
            HashMap map = e;
            a aVar = (a) map.get(str);
            if (aVar != null) {
                Intrinsics.checkNotNullParameter(this, "activity");
                com.perimeterx.mobile_sdk.session.d dVar = aVar.a;
                if (dVar != null) {
                    androidx.constraintlayout.core.widgets.analyzer.f fVar = androidx.constraintlayout.core.widgets.analyzer.f.j;
                    if (fVar != null && fVar.f() && (bVar = ((com.perimeterx.mobile_sdk.doctor_app.model.d) fVar.i).e) != null) {
                        bVar.e = true;
                    }
                    if (cookie == null || (token = dVar.b.g) == null) {
                        E.A(E.c(O.a), null, null, new n(dVar, null, 0), 3);
                    } else {
                        Intrinsics.checkNotNullParameter(token, "token");
                        Intrinsics.checkNotNullParameter(cookie, "cookie");
                        ArrayList arrayList = new ArrayList();
                        ReentrantLock reentrantLock = token.d;
                        reentrantLock.lock();
                        ArrayList arrayList2 = new ArrayList(token.c);
                        reentrantLock.unlock();
                        Iterator it2 = arrayList2.iterator();
                        Intrinsics.checkNotNullExpressionValue(it2, "iterator(...)");
                        while (it2.hasNext()) {
                            Object next = it2.next();
                            Intrinsics.checkNotNullExpressionValue(next, "next(...)");
                            com.perimeterx.mobile_sdk.models.d dVar2 = (com.perimeterx.mobile_sdk.models.d) next;
                            if (Intrinsics.b(dVar2.a, cookie.a)) {
                                arrayList.add(cookie);
                            } else {
                                arrayList.add(dVar2);
                            }
                        }
                        dVar.g(new com.perimeterx.mobile_sdk.models.f(token.a, token.b, arrayList));
                        dVar.m();
                    }
                }
                kotlin.jvm.internal.O.c(map).remove(this.c);
                finish();
            }
        }
    }
}
