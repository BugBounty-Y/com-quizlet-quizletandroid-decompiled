package com.pubmatic.sdk.webrendering.mraid;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Trace;
import android.view.View;
import androidx.annotation.NonNull;
import androidx.compose.animation.d0;
import com.pubmatic.sdk.common.log.POBLog;
import org.json.JSONException;

/* loaded from: classes2.dex */
public class e implements w, com.pubmatic.sdk.common.ui.a, com.pubmatic.sdk.common.ui.e, com.pubmatic.sdk.common.viewability.i, com.pubmatic.sdk.webrendering.ui.k {

    @NonNull
    private final String a;

    @NonNull
    private final POBMraidController b;

    @NonNull
    private final POBMraidBridge c;

    @NonNull
    private final com.pubmatic.sdk.webrendering.ui.i d;
    private com.pubmatic.sdk.common.base.d e;
    private boolean f;
    private View.OnLayoutChangeListener g;
    private com.pubmatic.sdk.webrendering.ui.a h;
    private com.pubmatic.sdk.common.viewability.b i;
    private String j;

    @NonNull
    private final Context k;
    private com.pubmatic.sdk.common.view.c l;
    private com.pubmatic.sdk.common.base.c m;
    private com.pubmatic.sdk.common.utility.n n;

    public class a implements com.pubmatic.sdk.common.view.a {
        public a() {
        }

        @Override // com.pubmatic.sdk.common.view.a
        public void onFocusChanged(boolean z) {
            if (e.this.h != null) {
                e.this.h.onVisibilityChange(z);
            }
        }
    }

    public class b implements com.pubmatic.sdk.common.viewability.c {
        final /* synthetic */ String a;
        final /* synthetic */ boolean b;

        public b(String str, boolean z) {
            this.a = str;
            this.b = z;
        }

        @Override // com.pubmatic.sdk.common.viewability.c
        public void onMeasurementScriptReceived(@NonNull String str) {
            StringBuilder sbY = android.support.v4.media.session.a.y("<script>", str, "</script>");
            sbY.append(this.a);
            e.this.d.loadHTML(sbY.toString(), e.this.j, this.b);
        }
    }

    public class c implements com.pubmatic.sdk.webrendering.ui.p {
        final /* synthetic */ com.pubmatic.sdk.webrendering.ui.q a;

        public c(com.pubmatic.sdk.webrendering.ui.q qVar) {
            this.a = qVar;
        }

        @Override // com.pubmatic.sdk.webrendering.ui.p
        public void onViewabilityChanged(boolean z) {
            if (z) {
                e.this.b();
                this.a.destroy();
            }
        }
    }

    public class d implements Runnable {
        public d() {
        }

        @Override // java.lang.Runnable
        public void run() throws JSONException {
            if (e.this.f) {
                e.this.c.setMraidState(j.DEFAULT);
            }
            e.this.b.initProperties(e.this.c, e.this.f);
            e.this.f = false;
        }
    }

    /* renamed from: com.pubmatic.sdk.webrendering.mraid.e$e, reason: collision with other inner class name */
    public class ViewOnLayoutChangeListenerC0022e implements View.OnLayoutChangeListener {
        public ViewOnLayoutChangeListenerC0022e() {
        }

        @Override // android.view.View.OnLayoutChangeListener
        public void onLayoutChange(View view, int i, int i2, int i3, int i4, int i5, int i6, int i7, int i8) {
            e.this.f();
        }
    }

    public class f implements com.pubmatic.sdk.common.utility.m {
        public f() {
        }

        @Override // com.pubmatic.sdk.common.utility.m
        public void onErrorOpenUrl(@NonNull String str) {
            POBLog.warn("POBMraidRenderer", "Error opening url %s", str);
        }

        @Override // com.pubmatic.sdk.common.utility.m
        public void onInternalBrowserClose(@NonNull String str) {
            e.this.onAdInteractionStopped();
        }

        @Override // com.pubmatic.sdk.common.utility.m
        public void onInternalBrowserOpen(@NonNull String str) {
            e.this.onAdInteractionStarted();
        }

        @Override // com.pubmatic.sdk.common.utility.m
        public void onLeaveApp(@NonNull String str) {
            e.this.onLeavingApplication();
        }
    }

    public class g implements Runnable {
        public g() {
        }

        @Override // java.lang.Runnable
        public void run() {
            if (e.this.i != null) {
                e.this.i.signalAdEvent(com.pubmatic.sdk.common.viewability.a.IMPRESSION);
            }
        }
    }

    @SuppressLint({"SetJavaScriptEnabled"})
    public e(@NonNull Context context, @NonNull String str, @NonNull com.pubmatic.sdk.common.view.c cVar, int i) {
        this.k = context;
        this.a = str;
        this.l = cVar;
        cVar.getSettings().setJavaScriptEnabled(true);
        cVar.getSettings().setCacheMode(2);
        cVar.setScrollBarStyle(0);
        com.pubmatic.sdk.webrendering.mraid.f fVar = new com.pubmatic.sdk.webrendering.mraid.f(this);
        fVar.disableMultipleOnPageFinished(true);
        com.pubmatic.sdk.webrendering.ui.i iVar = new com.pubmatic.sdk.webrendering.ui.i(cVar, fVar);
        this.d = iVar;
        iVar.setRendererViewListener(this);
        POBMraidBridge pOBMraidBridge = new POBMraidBridge(cVar);
        this.c = pOBMraidBridge;
        POBMraidController pOBMraidController = new POBMraidController(context, pOBMraidBridge, str, i);
        this.b = pOBMraidController;
        pOBMraidController.setMraidControllerListener(this);
        pOBMraidController.addInlineVideoSupportToWebView(cVar);
        e();
        a(pOBMraidController);
    }

    public static e createInstance(@NonNull Context context, @NonNull String str, int i) {
        com.pubmatic.sdk.common.view.c cVarCreateInstance = com.pubmatic.sdk.common.view.c.createInstance(context);
        if (cVarCreateInstance != null) {
            return new e(context, str, cVarCreateInstance, i);
        }
        return null;
    }

    @Override // com.pubmatic.sdk.webrendering.mraid.w, com.pubmatic.sdk.common.viewability.i
    public void addFriendlyObstructions(@NonNull View view, @NonNull com.pubmatic.sdk.common.viewability.h hVar) {
        com.pubmatic.sdk.common.viewability.b bVar = this.i;
        if (bVar != null) {
            bVar.addFriendlyObstructions(view, hVar);
        }
    }

    @Override // com.pubmatic.sdk.common.ui.a
    public void destroy() {
        invalidate();
        this.d.destroy();
    }

    public void invalidate() {
        this.b.destroy();
        com.pubmatic.sdk.common.view.c cVar = this.l;
        if (cVar != null) {
            cVar.removeOnLayoutChangeListener(this.g);
            this.l.setOnfocusChangedListener(null);
            this.l = null;
        }
        this.g = null;
        com.pubmatic.sdk.common.viewability.b bVar = this.i;
        if (bVar != null) {
            bVar.finishAdSession();
            this.i = null;
        }
    }

    @Override // com.pubmatic.sdk.common.ui.a
    public void invalidateExpiration() {
    }

    @Override // com.pubmatic.sdk.webrendering.mraid.w
    public boolean isUserInteracted(boolean z) {
        boolean zIsUserInteracted = this.d.isUserInteracted();
        if (z) {
            this.d.setUserInteracted(false);
        }
        return zIsUserInteracted;
    }

    @Override // com.pubmatic.sdk.webrendering.mraid.w
    public void onAdInteractionStarted() {
        com.pubmatic.sdk.common.base.d dVar = this.e;
        if (dVar != null) {
            dVar.onAdInteractionStarted();
        }
    }

    @Override // com.pubmatic.sdk.webrendering.mraid.w
    public void onAdInteractionStopped() {
        com.pubmatic.sdk.common.base.d dVar = this.e;
        if (dVar != null) {
            dVar.onAdInteractionStopped();
        }
    }

    @Override // com.pubmatic.sdk.webrendering.mraid.w
    public void onAdUnload() {
        com.pubmatic.sdk.common.base.d dVar = this.e;
        if (dVar != null) {
            dVar.onAdUnload();
        }
    }

    @Override // com.pubmatic.sdk.webrendering.mraid.w
    public void onAdViewChanged(View view) {
        com.pubmatic.sdk.common.viewability.b bVar = this.i;
        if (bVar != null) {
            bVar.setTrackView(view);
        }
    }

    @Override // com.pubmatic.sdk.webrendering.mraid.w
    public void onLeavingApplication() {
        com.pubmatic.sdk.common.base.d dVar = this.e;
        if (dVar != null) {
            dVar.onLeavingApplication();
        }
    }

    @Override // com.pubmatic.sdk.webrendering.mraid.w
    public void onMRAIDAdClick() {
        com.pubmatic.sdk.common.base.d dVar = this.e;
        if (dVar != null) {
            dVar.onRenderAdClick();
        }
    }

    @Override // com.pubmatic.sdk.webrendering.mraid.w
    public void onOpen(String str) {
        a(str);
    }

    @Override // com.pubmatic.sdk.common.ui.e, com.pubmatic.sdk.webrendering.ui.k
    public void onRenderProcessGone() {
        com.pubmatic.sdk.common.base.d dVar = this.e;
        if (dVar != null) {
            dVar.onRenderProcessGone();
        }
        invalidate();
        this.d.invalidateWebView();
    }

    @Override // com.pubmatic.sdk.common.ui.e
    public void onViewClicked(String str) {
        a(str);
    }

    @Override // com.pubmatic.sdk.common.ui.e
    public void onViewRendered(@NonNull View view) {
        Trace.endSection();
        if (this.a.equals("inline")) {
            this.b.close();
        }
        this.c.resetPropertyMap();
        this.f = true;
        if (this.a.equals("inline")) {
            f();
        }
        d();
        g();
        if (this.e != null) {
            a(this.k);
            this.e.onAdRender(view, this.m);
            if (!a()) {
                b();
            }
            com.pubmatic.sdk.common.base.c cVar = this.m;
            this.e.onAdReadyToRefresh(cVar != null ? cVar.getRefreshInterval() : 0);
        }
    }

    @Override // com.pubmatic.sdk.common.ui.e
    public void onViewRenderingFailed(@NonNull com.pubmatic.sdk.common.h hVar) {
        Trace.endSection();
        com.pubmatic.sdk.common.base.d dVar = this.e;
        if (dVar != null) {
            dVar.onAdRenderingFailed(hVar);
        }
    }

    @Override // com.pubmatic.sdk.webrendering.mraid.w, com.pubmatic.sdk.common.viewability.i
    public void removeFriendlyObstructions(View view) {
        com.pubmatic.sdk.common.viewability.b bVar = this.i;
        if (bVar != null) {
            bVar.removeFriendlyObstructions(view);
        }
    }

    @Override // com.pubmatic.sdk.common.ui.a
    public void renderAd(@NonNull com.pubmatic.sdk.common.base.c cVar) {
        Trace.beginSection("POB Mraid Parsing");
        this.m = cVar;
        if (a()) {
            c();
        }
        this.b.addCommandHandlers(this.c, false, this.m.isCompanion());
        String renderableContent = cVar.getRenderableContent();
        boolean zIsCompanion = cVar.isCompanion();
        if (zIsCompanion && !com.pubmatic.sdk.common.utility.o.isNullOrEmpty(renderableContent) && renderableContent.toLowerCase().startsWith("http")) {
            this.d.loadHTML(null, renderableContent, zIsCompanion);
            return;
        }
        Context applicationContext = this.k.getApplicationContext();
        com.pubmatic.sdk.common.models.f deviceInfo = com.pubmatic.sdk.common.i.getDeviceInfo(applicationContext);
        StringBuilder sbU = d0.u(C4074c.getMRAIDEnvironment(com.pubmatic.sdk.common.i.getAppInfo(applicationContext).getPackageName(), deviceInfo.getAdvertisingID(), deviceInfo.getLmtEnabled(), com.pubmatic.sdk.common.i.getSdkConfig().isCoppa()));
        sbU.append(cVar.getRenderableContent());
        String string = sbU.toString();
        com.pubmatic.sdk.common.viewability.b bVar = this.i;
        if (bVar != null) {
            bVar.omidJsServiceScript(this.k.getApplicationContext(), new b(string, zIsCompanion));
        } else {
            this.d.loadHTML(string, this.j, zIsCompanion);
        }
    }

    @Override // com.pubmatic.sdk.common.ui.a
    public void setAdRendererListener(com.pubmatic.sdk.common.base.d dVar) {
        this.e = dVar;
    }

    public void setBaseURL(String str) {
        this.j = str;
    }

    public void setHTMLMeasurementListener(com.pubmatic.sdk.common.viewability.b bVar) {
        this.i = bVar;
    }

    public void setRenderingTimeout(int i) {
        this.d.setRenderingTimeout(i);
    }

    public void signalImpressionEvent() {
        com.pubmatic.sdk.common.view.c cVar;
        if (this.i == null || (cVar = this.l) == null) {
            return;
        }
        cVar.postDelayed(new g(), 1000L);
    }

    private void b(String str) {
        if (this.n == null || com.pubmatic.sdk.common.utility.o.isNullOrEmpty(str) || "https://obplaceholder.click.com/".equals(str)) {
            POBLog.warn("POBMraidRenderer", "Click through url is missing.", new Object[0]);
        } else {
            this.n.open(str);
        }
    }

    private void c() {
        com.pubmatic.sdk.common.view.c cVar = this.l;
        if (cVar != null) {
            com.pubmatic.sdk.webrendering.ui.q qVar = new com.pubmatic.sdk.webrendering.ui.q((View) cVar, 1);
            qVar.setAllowViewTreeObserverRegistration(true);
            qVar.setOnExposureChangeWithThresholdListener(new c(qVar));
        }
    }

    private void d() {
        if (this.g != null || this.l == null) {
            POBLog.debug("POBMraidRenderer", "layoutChangeListener null", new Object[0]);
            return;
        }
        ViewOnLayoutChangeListenerC0022e viewOnLayoutChangeListenerC0022e = new ViewOnLayoutChangeListenerC0022e();
        this.g = viewOnLayoutChangeListenerC0022e;
        this.l.addOnLayoutChangeListener(viewOnLayoutChangeListenerC0022e);
    }

    private void e() {
        com.pubmatic.sdk.common.view.c cVar = this.l;
        if (cVar != null) {
            cVar.setOnfocusChangedListener(new a());
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void f() {
        com.pubmatic.sdk.common.view.c cVar = this.l;
        if (cVar != null) {
            cVar.post(new d());
        }
    }

    private void g() {
        com.pubmatic.sdk.common.view.c cVar;
        com.pubmatic.sdk.common.viewability.b bVar = this.i;
        if (bVar == null || (cVar = this.l) == null) {
            return;
        }
        bVar.startAdSession(cVar);
        this.i.signalAdEvent(com.pubmatic.sdk.common.viewability.a.LOADED);
        if (this.a.equals("inline")) {
            signalImpressionEvent();
        }
    }

    private void a(@NonNull com.pubmatic.sdk.webrendering.ui.a aVar) {
        this.h = aVar;
    }

    private void a(String str) {
        b(str);
        com.pubmatic.sdk.common.base.d dVar = this.e;
        if (dVar != null) {
            dVar.onRenderAdClick();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void b() {
        com.pubmatic.sdk.common.base.d dVar = this.e;
        if (dVar != null) {
            dVar.onAdImpression();
        }
    }

    private boolean a() {
        com.pubmatic.sdk.common.base.c cVar = this.m;
        return cVar != null && cVar.getDspId() == 80;
    }

    private void a(@NonNull Context context) {
        this.n = new com.pubmatic.sdk.common.utility.n(context, new f());
    }
}
