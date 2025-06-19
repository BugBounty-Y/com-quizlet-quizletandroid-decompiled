package com.quizlet.features.blocks.ui;

import android.content.Context;
import android.view.ViewGroup;
import android.webkit.WebSettings;
import android.webkit.WebView;
import androidx.compose.animation.d0;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.navigation.E;
import androidx.navigation.H;
import com.google.android.gms.internal.mlkit_vision_barcode.N5;
import com.quizlet.assembly.compose.buttons.C4087l;
import com.quizlet.assembly.compose.input.h;
import com.quizlet.assembly.compose.input.m;
import com.quizlet.assembly.compose.menu.g;
import com.quizlet.data.model.m2;
import com.quizlet.eventlogger.features.search.SearchType;
import com.quizlet.features.practicetest.navigation.i;
import com.quizlet.search.viewmodels.A;
import com.quizlet.search.viewmodels.AbstractC4797c;
import com.quizlet.search.viewmodels.D;
import com.quizlet.search.viewmodels.G;
import com.quizlet.search.viewmodels.u;
import com.quizlet.search.viewmodels.x;
import com.quizlet.ui.compose.C4815h;
import java.util.Map;
import kotlin.InterfaceC4938g;
import kotlin.Unit;
import kotlin.collections.C4930v;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes2.dex */
public final /* synthetic */ class b implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;
    public final /* synthetic */ Object d;
    public final /* synthetic */ Object e;
    public final /* synthetic */ Object f;
    public final /* synthetic */ Object g;
    public final /* synthetic */ Object h;
    public final /* synthetic */ Object i;

    public /* synthetic */ b(f fVar, e eVar, String str, com.quizlet.features.consent.onetrust.d dVar, a aVar, String str2, Map map, InterfaceC0773a0 interfaceC0773a0) {
        this.a = 0;
        this.d = fVar;
        this.e = eVar;
        this.b = str;
        this.f = dVar;
        this.g = aVar;
        this.c = str2;
        this.h = map;
        this.i = interfaceC0773a0;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r7v0, types: [java.lang.Object, java.util.Map] */
    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        Object obj2 = this.e;
        Object obj3 = this.f;
        Object obj4 = this.c;
        Object obj5 = this.b;
        ?? r7 = this.h;
        Object obj6 = this.g;
        Object obj7 = this.i;
        Object obj8 = this.d;
        switch (this.a) {
            case 0:
                Context context = (Context) obj;
                Intrinsics.checkNotNullParameter(context, "context");
                WebView webView = new WebView(context);
                webView.setLayoutParams(new ViewGroup.LayoutParams(-1, -1));
                webView.setWebViewClient((f) obj8);
                webView.setWebChromeClient((e) obj2);
                WebSettings settings = webView.getSettings();
                Intrinsics.checkNotNullExpressionValue(settings, "getSettings(...)");
                settings.setLoadsImagesAutomatically(true);
                settings.setJavaScriptEnabled(true);
                settings.setDomStorageEnabled(true);
                settings.setCacheMode(1);
                String userAgentString = settings.getUserAgentString();
                String versionName = (String) obj5;
                Intrinsics.checkNotNullParameter(versionName, "versionName");
                settings.setUserAgentString(userAgentString + d0.s(new Object[]{versionName}, 1, "[QWebView P/android;V/%s]", "format(...)"));
                webView.setFocusableInTouchMode(true);
                webView.setFocusable(true);
                webView.setVerticalScrollBarEnabled(true);
                ((com.quizlet.features.consent.onetrust.d) obj3).c(webView);
                webView.addJavascriptInterface((a) obj6, "gamesNativeHandler");
                webView.loadUrl((String) obj4, r7);
                ((InterfaceC0773a0) obj7).setValue(webView);
                break;
            case 1:
                E NavHost = (E) obj;
                Intrinsics.checkNotNullParameter(NavHost, "$this$NavHost");
                String str = (String) obj5;
                com.quizlet.features.practicetest.navigation.d dVar = (com.quizlet.features.practicetest.navigation.d) obj2;
                Function0 function0 = (Function0) obj3;
                H h = (H) obj6;
                N5.d(NavHost, new com.quizlet.features.practicetest.navigation.e(str), new androidx.compose.runtime.internal.d(true, -887188541, new h(dVar, function0, h, 11)));
                N5.d(NavHost, new i(str, (String) obj4, (String) obj8), new androidx.compose.runtime.internal.d(true, -954419540, new g((Object) dVar, (Object) h, (Object) r7, (Object) function0, 8)));
                N5.d(NavHost, com.quizlet.features.practicetest.navigation.g.a, new androidx.compose.runtime.internal.d(true, 216789131, new m(26, dVar, h)));
                N5.e(NavHost, com.quizlet.features.practicetest.navigation.f.a, new androidx.compose.runtime.internal.d(true, -1957605720, new h(h, (C) obj7, dVar, 12)));
                break;
            case 2:
                E NavHost2 = (E) obj;
                Intrinsics.checkNotNullParameter(NavHost2, "$this$NavHost");
                m2 m2Var = (m2) obj8;
                Function0 function02 = (Function0) obj2;
                H h2 = (H) obj4;
                Function1 function1 = (Function1) obj3;
                Function0 function03 = (Function0) obj6;
                N5.d(NavHost2, new com.quizlet.features.universaluploadflow.navigation.h(m2Var), new androidx.compose.runtime.internal.d(true, 142150020, new C4087l(m2Var, function02, (com.quizlet.features.universaluploadflow.navigation.e) obj5, h2, function1, function03, (Function0) r7, (Function0) obj7, 3)));
                N5.d(NavHost2, com.quizlet.features.universaluploadflow.navigation.g.a, new androidx.compose.runtime.internal.d(true, -772216019, new com.quizlet.features.universaluploadflow.navigation.b(h2, function02, function1, function03, 0)));
                N5.d(NavHost2, com.quizlet.features.universaluploadflow.navigation.f.a, new androidx.compose.runtime.internal.d(true, 1566604364, new com.quizlet.features.universaluploadflow.navigation.b(h2, function02, function1, function03, 1)));
                break;
            default:
                SearchType searchType = ((C4815h) ((kotlinx.collections.immutable.e) obj8).get(((Integer) obj).intValue())).b;
                if (searchType == null) {
                    searchType = null;
                }
                ((InterfaceC0773a0) obj7).setValue(searchType);
                ((Function2) obj2).invoke(searchType, C4930v.c(new AbstractC4797c[]{(A) obj5, (D) obj4, (x) obj3, (G) obj6, (u) r7}));
                break;
        }
        return Unit.a;
    }

    public /* synthetic */ b(Object obj, InterfaceC4938g interfaceC4938g, Object obj2, Object obj3, Object obj4, Object obj5, Object obj6, Object obj7, int i) {
        this.a = i;
        this.d = obj;
        this.e = interfaceC4938g;
        this.b = obj2;
        this.c = obj3;
        this.f = obj4;
        this.g = obj5;
        this.h = obj6;
        this.i = obj7;
    }

    public /* synthetic */ b(String str, String str2, String str3, com.quizlet.features.practicetest.navigation.d dVar, Function0 function0, H h, Function0 function02, C c) {
        this.a = 1;
        this.b = str;
        this.c = str2;
        this.d = str3;
        this.e = dVar;
        this.f = function0;
        this.g = h;
        this.h = function02;
        this.i = c;
    }
}
