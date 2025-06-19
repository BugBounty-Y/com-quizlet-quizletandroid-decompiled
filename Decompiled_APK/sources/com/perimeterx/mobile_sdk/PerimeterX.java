package com.perimeterx.mobile_sdk;

import android.app.Application;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import androidx.annotation.Keep;
import androidx.constraintlayout.core.widgets.analyzer.f;
import com.google.firebase.messaging.u;
import com.perimeterx.mobile_sdk.doctor_app.model.c;
import com.perimeterx.mobile_sdk.local_data.w;
import com.perimeterx.mobile_sdk.local_data.x;
import com.perimeterx.mobile_sdk.main.PXPolicy;
import com.perimeterx.mobile_sdk.session.d;
import com.perimeterx.mobile_sdk.session.l;
import com.perimeterx.mobile_sdk.session.m;
import com.perimeterx.mobile_sdk.session.r;
import com.perimeterx.mobile_sdk.session.s;
import com.perimeterx.mobile_sdk.session.z;
import com.perimeterx.mobile_sdk.web_view_interception.PXJavaScriptInterface;
import com.perimeterx.mobile_sdk.web_view_interception.g;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.B;
import kotlin.coroutines.h;
import kotlin.coroutines.n;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Regex;
import kotlinx.coroutines.E;
import kotlinx.coroutines.O;
import org.jetbrains.annotations.NotNull;
import org.json.JSONException;
import org.json.JSONObject;

@Keep
@Metadata
/* loaded from: classes2.dex */
public final class PerimeterX {

    @NotNull
    public static final PerimeterX INSTANCE = new PerimeterX();

    private PerimeterX() {
    }

    public static /* synthetic */ boolean canHandleResponse$default(PerimeterX perimeterX, String str, String str2, int i, Object obj) {
        if ((i & 2) != 0) {
            str2 = null;
        }
        return perimeterX.canHandleResponse(str, str2);
    }

    public static /* synthetic */ boolean handleResponse$default(PerimeterX perimeterX, String str, String str2, Function1 function1, int i, Object obj) {
        if ((i & 2) != 0) {
            str2 = null;
        }
        return perimeterX.handleResponse(str, str2, function1);
    }

    public static /* synthetic */ HashMap headersForURLRequest$default(PerimeterX perimeterX, String str, int i, Object obj) {
        if ((i & 1) != 0) {
            str = null;
        }
        return perimeterX.headersForURLRequest(str);
    }

    public static /* synthetic */ void registerOutgoingUrlRequest$default(PerimeterX perimeterX, String str, String str2, int i, Object obj) throws Exception {
        if ((i & 2) != 0) {
            str2 = null;
        }
        perimeterX.registerOutgoingUrlRequest(str, str2);
    }

    public static /* synthetic */ void setAdditionalData$default(PerimeterX perimeterX, HashMap map, String str, int i, Object obj) throws Exception {
        if ((i & 2) != 0) {
            str = null;
        }
        perimeterX.setAdditionalData(map, str);
    }

    public static /* synthetic */ void setCustomParameters$default(PerimeterX perimeterX, HashMap map, String str, int i, Object obj) throws Exception {
        if ((i & 2) != 0) {
            str = null;
        }
        perimeterX.setCustomParameters(map, str);
    }

    public static /* synthetic */ void setUserId$default(PerimeterX perimeterX, String str, String str2, int i, Object obj) throws Exception {
        if ((i & 2) != 0) {
            str2 = null;
        }
        perimeterX.setUserId(str, str2);
    }

    public static /* synthetic */ String vid$default(PerimeterX perimeterX, String str, int i, Object obj) {
        if ((i & 1) != 0) {
            str = null;
        }
        return perimeterX.vid(str);
    }

    @NotNull
    public final String blockedErrorBody() throws JSONException {
        JSONObject jSONObject = new JSONObject();
        jSONObject.putOpt("px_error", "the request was blocked by perimeterx service");
        String string = jSONObject.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }

    public final boolean canHandleResponse(@NotNull String response, String str) throws Throwable {
        Intrinsics.checkNotNullParameter(response, "response");
        l lVar = l.a;
        Intrinsics.checkNotNullParameter(response, "response");
        d dVarA = l.a(str);
        if (dVarA == null) {
            return false;
        }
        Intrinsics.checkNotNullParameter(response, "response");
        dVarA.g.getClass();
        return com.google.mlkit.common.sdkinternal.model.a.e(response) != null;
    }

    @NotNull
    public final String challengeCancelledErrorBody() throws JSONException {
        JSONObject jSONObject = new JSONObject();
        jSONObject.putOpt("px_error", "the request was blocked by perimeterx service; challenge was cancelled by the user");
        String string = jSONObject.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }

    @NotNull
    public final String challengeSolvedErrorBody() throws JSONException {
        JSONObject jSONObject = new JSONObject();
        jSONObject.putOpt("px_error", "the request was blocked by perimeterx service; user has solved the challenge successfully");
        String string = jSONObject.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }

    public final boolean handleResponse(@NotNull String response, String str, Function1<? super PerimeterXChallengeResult, Unit> function1) throws Throwable {
        Intrinsics.checkNotNullParameter(response, "response");
        l lVar = l.a;
        Intrinsics.checkNotNullParameter(response, "response");
        d dVarA = l.a(str);
        if (dVarA == null) {
            return false;
        }
        Intrinsics.checkNotNullParameter(response, "response");
        dVarA.g.getClass();
        com.perimeterx.mobile_sdk.block.b bVarE = com.google.mlkit.common.sdkinternal.model.a.e(response);
        if (bVarE == null) {
            return false;
        }
        E.A(E.c(O.a), null, null, new s(dVarA, bVarE, function1, null), 3);
        return true;
    }

    public final HashMap<String, String> headersForURLRequest(String str) throws Throwable {
        l lVar = l.a;
        d dVarA = l.a(str);
        if (dVarA != null) {
            return dVarA.o();
        }
        return null;
    }

    public final boolean isChallengeCancelledError(@NotNull String response) {
        Intrinsics.checkNotNullParameter(response, "response");
        try {
            return Intrinsics.b(new JSONObject(response).getString("px_error"), "the request was blocked by perimeterx service; challenge was cancelled by the user");
        } catch (Exception unused) {
            return false;
        }
    }

    public final boolean isChallengeSolvedError(@NotNull String response) {
        Intrinsics.checkNotNullParameter(response, "response");
        try {
            return Intrinsics.b(new JSONObject(response).getString("px_error"), "the request was blocked by perimeterx service; user has solved the challenge successfully");
        } catch (Exception unused) {
            return false;
        }
    }

    public final boolean isRequestBlockedError(@NotNull String response) {
        Intrinsics.checkNotNullParameter(response, "response");
        try {
            return Intrinsics.b(new JSONObject(response).getString("px_error"), "the request was blocked by perimeterx service");
        } catch (Exception unused) {
            return false;
        }
    }

    public final void registerOutgoingUrlRequest(@NotNull String url, String str) throws Exception {
        Intrinsics.checkNotNullParameter(url, "url");
        l lVar = l.a;
        Intrinsics.checkNotNullParameter(url, "url");
        d dVarA = l.a(str);
        if (dVarA == null) {
            throw new Exception(PerimeterXErrorCode.START_WAS_NOT_CALLED.message$PerimeterX_release());
        }
        dVarA.p(url);
    }

    @NotNull
    public final String sdkVersion() {
        return "3.4.0";
    }

    public final void setAdditionalData(@NotNull HashMap<String, String> parameters, String str) throws Exception {
        com.perimeterx.mobile_sdk.doctor_app.model.b bVar;
        Intrinsics.checkNotNullParameter(parameters, "parameters");
        l lVar = l.a;
        Intrinsics.checkNotNullParameter(parameters, "parameters");
        c.h = true;
        f fVar = f.j;
        if (fVar != null && (bVar = ((com.perimeterx.mobile_sdk.doctor_app.model.d) fVar.i).e) != null) {
            bVar.j = true;
        }
        d dVarA = l.a(str);
        if (dVarA == null) {
            throw new Exception(PerimeterXErrorCode.START_WAS_NOT_CALLED.message$PerimeterX_release());
        }
        Intrinsics.checkNotNullParameter(parameters, "parameters");
        HashMap map = new HashMap();
        for (Map.Entry<String, String> entry : parameters.entrySet()) {
            map.put(entry.getKey(), entry.getValue());
        }
        h hVar = null;
        E.D(n.a, new z(dVarA, map, hVar, 0));
        x xVar = x.f;
        String str2 = dVarA.b.a;
        dVarA.i.getClass();
        String strA = w.a(xVar, str2);
        if (strA == null || strA.length() == 0) {
            strA = null;
        }
        if (strA != null) {
            E.A(E.c(O.a), null, null, new r(dVarA, new com.perimeterx.mobile_sdk.models.a(strA, null, null), hVar, 2), 3);
        }
    }

    public final void setCustomParameters(@NotNull HashMap<String, String> parameters, String str) throws Exception {
        Intrinsics.checkNotNullParameter(parameters, "parameters");
        l lVar = l.a;
        Intrinsics.checkNotNullParameter(parameters, "parameters");
        d dVarA = l.a(str);
        if (dVarA == null) {
            throw new Exception(PerimeterXErrorCode.START_WAS_NOT_CALLED.message$PerimeterX_release());
        }
        Intrinsics.checkNotNullParameter(parameters, "parameters");
        HashMap map = new HashMap();
        for (Map.Entry<String, String> entry : parameters.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();
            if (new Regex("^custom_param([1-9]|10)$").e(key)) {
                map.put(key, value);
            }
        }
        E.D(n.a, new z(dVarA, map, null, 1));
    }

    public final void setUserId(String str, String str2) throws Exception {
        d dVarA = l.a(str2);
        if (dVarA == null) {
            throw new Exception(PerimeterXErrorCode.START_WAS_NOT_CALLED.message$PerimeterX_release());
        }
        h hVar = null;
        if (str == null || str.length() <= 0) {
            str = null;
        }
        x xVar = x.f;
        m mVar = dVarA.b;
        String str3 = mVar.a;
        dVarA.i.getClass();
        String strA = w.a(xVar, str3);
        if (strA == null || strA.length() == 0) {
            strA = null;
        }
        if (str == null) {
            if (strA != null) {
                w.c(strA, x.g, mVar.a);
                w.c(null, xVar, mVar.a);
                return;
            }
            return;
        }
        if (strA == null) {
            w.c(str, xVar, mVar.a);
            E.A(E.c(O.a), null, null, new r(dVarA, new com.perimeterx.mobile_sdk.models.a(str, null, null), hVar, 0), 3);
        } else {
            if (str.equals(strA)) {
                return;
            }
            w.c(strA, x.g, mVar.a);
            w.c(str, xVar, mVar.a);
            E.A(E.c(O.a), null, null, new r(dVarA, new com.perimeterx.mobile_sdk.models.a(str, strA, null), hVar, 1), 3);
        }
    }

    public final void setupWebView(@NotNull WebView webView, WebViewClient webViewClient) {
        com.perimeterx.mobile_sdk.web_view_interception.b bVar;
        Intrinsics.checkNotNullParameter(webView, "webView");
        l lVar = l.a;
        Intrinsics.checkNotNullParameter(webView, "webView");
        u uVar = l.d;
        uVar.getClass();
        Intrinsics.checkNotNullParameter(webView, "webView");
        ReentrantLock reentrantLock = (ReentrantLock) uVar.d;
        reentrantLock.lock();
        ArrayList arrayList = (ArrayList) uVar.c;
        Iterator it2 = arrayList.iterator();
        Intrinsics.checkNotNullExpressionValue(it2, "iterator(...)");
        while (true) {
            if (!it2.hasNext()) {
                bVar = null;
                break;
            }
            Object next = it2.next();
            Intrinsics.checkNotNullExpressionValue(next, "next(...)");
            bVar = (com.perimeterx.mobile_sdk.web_view_interception.b) next;
            if (Intrinsics.b(bVar.a, webView)) {
                break;
            }
        }
        if (bVar == null) {
            arrayList.add(new com.perimeterx.mobile_sdk.web_view_interception.b(webView));
        }
        reentrantLock.unlock();
        g gVar = new g();
        gVar.b = uVar;
        gVar.a = webViewClient;
        webView.setWebViewClient(gVar);
        webView.getSettings().setJavaScriptEnabled(true);
        PXJavaScriptInterface pXJavaScriptInterface = new PXJavaScriptInterface();
        pXJavaScriptInterface.get_internal$PerimeterX_release().a = uVar;
        webView.addJavascriptInterface(pXJavaScriptInterface, "pxCaptcha");
    }

    public final void start(@NotNull Application application, @NotNull String appId, PerimeterXDelegate perimeterXDelegate, @NotNull PXPolicy policy) throws Exception {
        Intrinsics.checkNotNullParameter(application, "application");
        Intrinsics.checkNotNullParameter(appId, "appId");
        Intrinsics.checkNotNullParameter(policy, "policy");
        l.a.e(application, B.f(appId), perimeterXDelegate, policy);
    }

    public final String vid(String str) throws Throwable {
        l lVar = l.a;
        d dVarA = l.a(str);
        if (dVarA != null) {
            return dVarA.r();
        }
        return null;
    }

    public final void start(@NotNull Application application, @NotNull ArrayList<String> appIds, PerimeterXDelegate perimeterXDelegate, @NotNull PXPolicy policy) throws Exception {
        Intrinsics.checkNotNullParameter(application, "application");
        Intrinsics.checkNotNullParameter(appIds, "appIds");
        Intrinsics.checkNotNullParameter(policy, "policy");
        l.a.e(application, appIds, perimeterXDelegate, policy);
    }
}
