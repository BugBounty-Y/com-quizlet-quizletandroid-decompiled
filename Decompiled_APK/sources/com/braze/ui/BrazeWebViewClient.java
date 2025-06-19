package com.braze.ui;

import android.content.Context;
import android.content.res.AssetManager;
import android.net.Uri;
import android.os.Bundle;
import android.webkit.RenderProcessGoneDetail;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import androidx.camera.camera2.internal.T;
import androidx.glance.appwidget.protobuf.Z;
import com.braze.BrazeInternal;
import com.braze.coroutine.BrazeCoroutineScope;
import com.braze.models.inappmessage.IInAppMessage;
import com.braze.models.outgoing.BrazeProperties;
import com.braze.requests.framework.o;
import com.braze.support.BrazeFileUtils;
import com.braze.support.BrazeLogger;
import com.braze.support.w;
import com.braze.ui.banners.listeners.IBannerWebViewClientListener;
import com.braze.ui.inappmessage.BrazeInAppMessageManager;
import com.braze.ui.inappmessage.listeners.IInAppMessageWebViewClientListener;
import com.braze.ui.inappmessage.listeners.IWebViewClientStateListener;
import com.braze.ui.support.UriUtils;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;
import java.io.File;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.InterfaceC4935d;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;
import kotlinx.coroutines.InterfaceC5025j0;
import kotlinx.coroutines.O;
import kotlinx.coroutines.internal.m;
import org.jetbrains.annotations.NotNull;
import org.json.JSONException;

@Metadata
/* loaded from: classes.dex */
public abstract class BrazeWebViewClient extends WebViewClient {

    @NotNull
    public static final Companion Companion = new Companion(null);

    @NotNull
    private final androidx.webkit.g assetLoader;

    @NotNull
    private final Context context;

    @NotNull
    private final AtomicBoolean hasCalledPageFinishedOnListener;
    private boolean hasPageFinishedLoading;
    private final IInAppMessage inAppMessage;
    private final IInAppMessageWebViewClientListener inAppMessageWebViewClientListener;
    private InterfaceC5025j0 markPageFinishedJob;
    private final int maxOnPageFinishedWaitTimeMs;

    @NotNull
    private final Type type;
    private IWebViewClientStateListener webViewClientStateListener;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final Bundle getBundleFromUrl(@NotNull String url) {
            Intrinsics.checkNotNullParameter(url, "url");
            Bundle bundle = new Bundle();
            if (!StringsKt.O(url)) {
                Uri uri = Uri.parse(url);
                Intrinsics.d(uri);
                for (Map.Entry<String, String> entry : UriUtils.getQueryParameters(uri).entrySet()) {
                    bundle.putString(entry.getKey(), entry.getValue());
                }
            }
            return bundle;
        }

        public final String parseCustomEventNameFromQueryBundle(@NotNull Bundle queryBundle) {
            Intrinsics.checkNotNullParameter(queryBundle, "queryBundle");
            return queryBundle.getString("name");
        }

        @NotNull
        public final BrazeProperties parsePropertiesFromQueryBundle(@NotNull Bundle queryBundle) throws JSONException {
            String string;
            Intrinsics.checkNotNullParameter(queryBundle, "queryBundle");
            BrazeProperties brazeProperties = new BrazeProperties();
            for (String str : queryBundle.keySet()) {
                if (!Intrinsics.b(str, "name") && (string = queryBundle.getString(str, null)) != null && !StringsKt.O(string)) {
                    Intrinsics.d(str);
                    brazeProperties.addProperty(str, string);
                }
            }
            return brazeProperties;
        }

        private Companion() {
        }
    }

    /* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
    /* JADX WARN: Unknown enum class pattern. Please report as an issue! */
    @Metadata
    public static final class Type {
        private static final /* synthetic */ kotlin.enums.a $ENTRIES;
        private static final /* synthetic */ Type[] $VALUES;
        public static final Type BANNER = new Type("BANNER", 0);
        public static final Type IN_APP_MESSAGE = new Type("IN_APP_MESSAGE", 1);

        private static final /* synthetic */ Type[] $values() {
            return new Type[]{BANNER, IN_APP_MESSAGE};
        }

        static {
            Type[] typeArr$values = $values();
            $VALUES = typeArr$values;
            $ENTRIES = AbstractC3328d.f(typeArr$values);
        }

        private Type(String str, int i) {
        }

        public static Type valueOf(String str) {
            return (Type) Enum.valueOf(Type.class, str);
        }

        public static Type[] values() {
            return (Type[]) $VALUES.clone();
        }
    }

    @Metadata
    public /* synthetic */ class WhenMappings {
        public static final /* synthetic */ int[] $EnumSwitchMapping$0;

        static {
            int[] iArr = new int[Type.values().length];
            try {
                iArr[Type.IN_APP_MESSAGE.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                iArr[Type.BANNER.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            $EnumSwitchMapping$0 = iArr;
        }
    }

    @Metadata
    @kotlin.coroutines.jvm.internal.e(c = "com.braze.ui.BrazeWebViewClient$setWebViewClientStateListener$1", f = "BrazeWebViewClient.kt", l = {159}, m = "invokeSuspend")
    /* renamed from: com.braze.ui.BrazeWebViewClient$setWebViewClientStateListener$1, reason: invalid class name */
    public static final class AnonymousClass1 extends i implements Function1<kotlin.coroutines.h<? super Unit>, Object> {
        int label;

        @Metadata
        @kotlin.coroutines.jvm.internal.e(c = "com.braze.ui.BrazeWebViewClient$setWebViewClientStateListener$1$1", f = "BrazeWebViewClient.kt", l = {}, m = "invokeSuspend")
        /* renamed from: com.braze.ui.BrazeWebViewClient$setWebViewClientStateListener$1$1, reason: invalid class name and collision with other inner class name */
        public static final class C00001 extends i implements Function2<C, kotlin.coroutines.h<? super Unit>, Object> {
            int label;
            final /* synthetic */ BrazeWebViewClient this$0;

            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            public C00001(BrazeWebViewClient brazeWebViewClient, kotlin.coroutines.h<? super C00001> hVar) {
                super(2, hVar);
                this.this$0 = brazeWebViewClient;
            }

            @Override // kotlin.coroutines.jvm.internal.a
            public final kotlin.coroutines.h<Unit> create(Object obj, kotlin.coroutines.h<?> hVar) {
                return new C00001(this.this$0, hVar);
            }

            @Override // kotlin.coroutines.jvm.internal.a
            public final Object invokeSuspend(Object obj) {
                kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
                if (this.label != 0) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
                this.this$0.markPageFinished();
                return Unit.a;
            }

            @Override // kotlin.jvm.functions.Function2
            public final Object invoke(C c, kotlin.coroutines.h<? super Unit> hVar) {
                return ((C00001) create(c, hVar)).invokeSuspend(Unit.a);
            }
        }

        public AnonymousClass1(kotlin.coroutines.h<? super AnonymousClass1> hVar) {
            super(1, hVar);
        }

        @Override // kotlin.coroutines.jvm.internal.a
        public final kotlin.coroutines.h<Unit> create(kotlin.coroutines.h<?> hVar) {
            return BrazeWebViewClient.this.new AnonymousClass1(hVar);
        }

        @Override // kotlin.coroutines.jvm.internal.a
        public final Object invokeSuspend(Object obj) {
            kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
            int i = this.label;
            if (i == 0) {
                Z.e(obj);
                kotlinx.coroutines.scheduling.e eVar = O.a;
                kotlinx.coroutines.android.d dVar = m.a;
                C00001 c00001 = new C00001(BrazeWebViewClient.this, null);
                this.label = 1;
                if (E.J(dVar, c00001, this) == aVar) {
                    return aVar;
                }
            } else {
                if (i != 1) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                Z.e(obj);
            }
            return Unit.a;
        }

        @Override // kotlin.jvm.functions.Function1
        public final Object invoke(kotlin.coroutines.h<? super Unit> hVar) {
            return ((AnonymousClass1) create(hVar)).invokeSuspend(Unit.a);
        }
    }

    public BrazeWebViewClient(@NotNull Context context, @NotNull Type type, IInAppMessage iInAppMessage, IInAppMessageWebViewClientListener iInAppMessageWebViewClientListener, IBannerWebViewClientListener iBannerWebViewClientListener, String str) {
        androidx.webkit.g gVar;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(type, "type");
        this.context = context;
        this.type = type;
        this.inAppMessage = iInAppMessage;
        this.inAppMessageWebViewClientListener = iInAppMessageWebViewClientListener;
        this.hasCalledPageFinishedOnListener = new AtomicBoolean(false);
        this.maxOnPageFinishedWaitTimeMs = BrazeInternal.INSTANCE.getConfigurationProvider(context).getInAppMessageWebViewClientOnPageFinishedMaxWaitMs();
        if (str != null) {
            ArrayList arrayList = new ArrayList();
            arrayList.add(new androidx.core.util.c("/", new androidx.webkit.e(context, new File(str))));
            ArrayList arrayList2 = new ArrayList();
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                androidx.core.util.c cVar = (androidx.core.util.c) it2.next();
                arrayList2.add(new androidx.webkit.f((String) cVar.a, (androidx.webkit.e) cVar.b));
            }
            gVar = new androidx.webkit.g(arrayList2);
        } else {
            File file = new File(context.getCacheDir(), "ab_triggers");
            ArrayList arrayList3 = new ArrayList();
            arrayList3.add(new androidx.core.util.c("/ab_triggers/", new androidx.webkit.e(context, file)));
            ArrayList arrayList4 = new ArrayList();
            Iterator it3 = arrayList3.iterator();
            while (it3.hasNext()) {
                androidx.core.util.c cVar2 = (androidx.core.util.c) it3.next();
                arrayList4.add(new androidx.webkit.f((String) cVar2.a, (androidx.webkit.e) cVar2.b));
            }
            gVar = new androidx.webkit.g(arrayList4);
        }
        this.assetLoader = gVar;
    }

    private final void appendBridgeJavascript(WebView webView) {
        try {
            AssetManager assets = this.context.getAssets();
            Intrinsics.checkNotNullExpressionValue(assets, "getAssets(...)");
            webView.loadUrl("javascript:" + BrazeFileUtils.getAssetFileStringContents(assets, "braze-html-bridge.js"));
        } catch (Exception e) {
            if (this.type == Type.IN_APP_MESSAGE) {
                BrazeInAppMessageManager.Companion.getInstance().hideCurrentlyDisplayingInAppMessage(false);
            }
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new o(this, 12), 4, (Object) null);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String appendBridgeJavascript$lambda$3(BrazeWebViewClient brazeWebViewClient) {
        return "Failed to get HTML " + brazeWebViewClient.type.name() + " javascript additions";
    }

    private final void handleQueryAction(String str, Uri uri, Bundle bundle) {
        IInAppMessage iInAppMessage;
        IInAppMessageWebViewClientListener iInAppMessageWebViewClientListener;
        IInAppMessage iInAppMessage2;
        IInAppMessageWebViewClientListener iInAppMessageWebViewClientListener2;
        IInAppMessage iInAppMessage3;
        IInAppMessageWebViewClientListener iInAppMessageWebViewClientListener3;
        String authority = uri.getAuthority();
        if (authority == null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.images.h(uri, 5), 7, (Object) null);
            return;
        }
        int iHashCode = authority.hashCode();
        if (iHashCode == -1801488983) {
            if (authority.equals("customEvent") && this.type == Type.IN_APP_MESSAGE && (iInAppMessage = this.inAppMessage) != null && (iInAppMessageWebViewClientListener = this.inAppMessageWebViewClientListener) != null) {
                iInAppMessageWebViewClientListener.onCustomEventAction(iInAppMessage, str, bundle);
                return;
            }
            return;
        }
        if (iHashCode == 3138974) {
            if (authority.equals("feed") && this.type == Type.IN_APP_MESSAGE && (iInAppMessage2 = this.inAppMessage) != null && (iInAppMessageWebViewClientListener2 = this.inAppMessageWebViewClientListener) != null) {
                iInAppMessageWebViewClientListener2.onNewsfeedAction(iInAppMessage2, str, bundle);
                return;
            }
            return;
        }
        if (iHashCode == 94756344 && authority.equals("close") && this.type == Type.IN_APP_MESSAGE && (iInAppMessage3 = this.inAppMessage) != null && (iInAppMessageWebViewClientListener3 = this.inAppMessageWebViewClientListener) != null) {
            iInAppMessageWebViewClientListener3.onCloseAction(iInAppMessage3, str, bundle);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String handleQueryAction$lambda$10(Uri uri) {
        return android.support.v4.media.session.a.h(uri, "Uri authority was null. Uri: ");
    }

    private final boolean handleUrlOverride(String str) {
        IInAppMessageWebViewClientListener iInAppMessageWebViewClientListener;
        Type type = this.type;
        String str2 = (type == Type.IN_APP_MESSAGE && this.inAppMessageWebViewClientListener == null) ? "BrazeWebViewClient was given null IInAppMessageWebViewClientListener listener. Returning true." : type == Type.BANNER ? "BrazeWebViewClient was given null IBannerWebViewClientListener listener. Returning true." : StringsKt.O(str) ? "BrazeWebViewClient.shouldOverrideUrlLoading was given blank url. Returning true." : null;
        if (str2 != null) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new w(str2, 26), 6, (Object) null);
            return true;
        }
        Uri uri = Uri.parse(str);
        Bundle bundleFromUrl = Companion.getBundleFromUrl(str);
        if (uri.getScheme() != null && Intrinsics.b(uri.getScheme(), "appboy")) {
            handleQueryAction(str, uri, bundleFromUrl);
            return true;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.images.h(uri, 4), 7, (Object) null);
        int i = WhenMappings.$EnumSwitchMapping$0[this.type.ordinal()];
        if (i == 1) {
            IInAppMessage iInAppMessage = this.inAppMessage;
            if (iInAppMessage != null && (iInAppMessageWebViewClientListener = this.inAppMessageWebViewClientListener) != null) {
                iInAppMessageWebViewClientListener.onOtherUrlAction(iInAppMessage, str, bundleFromUrl);
            }
        } else if (i != 2) {
            throw new NoWhenBranchMatchedException();
        }
        return true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String handleUrlOverride$lambda$7$lambda$6(String str) {
        return str;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String handleUrlOverride$lambda$8(Uri uri) {
        return android.support.v4.media.session.a.h(uri, "Uri scheme was null or not an appboy url. Uri: ");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void markPageFinished() {
        IWebViewClientStateListener iWebViewClientStateListener = this.webViewClientStateListener;
        if (iWebViewClientStateListener == null || !this.hasCalledPageFinishedOnListener.compareAndSet(false, true)) {
            return;
        }
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new com.braze.triggers.managers.i(18), 6, (Object) null);
        ((T) iWebViewClientStateListener).i();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String markPageFinished$lambda$5$lambda$4() {
        return "Page may not have finished loading, but max wait time has expired. Calling onPageFinished on listener.";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String onPageFinished$lambda$2$lambda$1() {
        return "Page has finished loading. Calling onPageFinished on listener";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final String onRenderProcessGone$lambda$14() {
        return "The webview rendering process crashed, returning true";
    }

    @Override // android.webkit.WebViewClient
    public void onPageFinished(@NotNull WebView view, @NotNull String url) {
        BrazeWebViewClient brazeWebViewClient;
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(url, "url");
        super.onPageFinished(view, url);
        appendBridgeJavascript(view);
        IWebViewClientStateListener iWebViewClientStateListener = this.webViewClientStateListener;
        if (iWebViewClientStateListener == null || !this.hasCalledPageFinishedOnListener.compareAndSet(false, true)) {
            brazeWebViewClient = this;
        } else {
            brazeWebViewClient = this;
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) brazeWebViewClient, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new com.braze.triggers.managers.i(20), 6, (Object) null);
            ((T) iWebViewClientStateListener).i();
        }
        brazeWebViewClient.hasPageFinishedLoading = true;
        InterfaceC5025j0 interfaceC5025j0 = brazeWebViewClient.markPageFinishedJob;
        if (interfaceC5025j0 != null) {
            interfaceC5025j0.j(null);
        }
        brazeWebViewClient.markPageFinishedJob = null;
    }

    @Override // android.webkit.WebViewClient
    public boolean onRenderProcessGone(@NotNull WebView view, @NotNull RenderProcessGoneDetail detail) {
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(detail, "detail");
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.I, (Throwable) null, false, (Function0) new com.braze.triggers.managers.i(19), 6, (Object) null);
        return true;
    }

    public final void setWebViewClientStateListener(IWebViewClientStateListener iWebViewClientStateListener) {
        if (iWebViewClientStateListener != null && this.hasPageFinishedLoading && this.hasCalledPageFinishedOnListener.compareAndSet(false, true)) {
            ((T) iWebViewClientStateListener).i();
        } else {
            this.markPageFinishedJob = BrazeCoroutineScope.launchDelayed$default(BrazeCoroutineScope.INSTANCE, Integer.valueOf(this.maxOnPageFinishedWaitTimeMs), null, new AnonymousClass1(null), 2, null);
        }
        this.webViewClientStateListener = iWebViewClientStateListener;
    }

    @Override // android.webkit.WebViewClient
    public WebResourceResponse shouldInterceptRequest(WebView webView, WebResourceRequest webResourceRequest) {
        if (webResourceRequest != null) {
            return this.assetLoader.a(webResourceRequest.getUrl());
        }
        return null;
    }

    @Override // android.webkit.WebViewClient
    public boolean shouldOverrideUrlLoading(@NotNull WebView view, @NotNull WebResourceRequest request) {
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(request, "request");
        String string = request.getUrl().toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return handleUrlOverride(string);
    }

    @Override // android.webkit.WebViewClient
    @InterfaceC4935d
    public WebResourceResponse shouldInterceptRequest(WebView webView, String str) {
        return this.assetLoader.a(Uri.parse(str));
    }

    @Override // android.webkit.WebViewClient
    @InterfaceC4935d
    public boolean shouldOverrideUrlLoading(@NotNull WebView view, @NotNull String url) {
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(url, "url");
        return handleUrlOverride(url);
    }
}
