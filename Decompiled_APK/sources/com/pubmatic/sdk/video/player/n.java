package com.pubmatic.sdk.video.player;

import android.content.Context;
import android.content.MutableContextWrapper;
import android.os.Build;
import android.os.Handler;
import android.os.Trace;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageButton;
import android.widget.TextView;
import androidx.annotation.NonNull;
import com.amazon.device.ads.DTBAdSize;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.video.vastmodels.j;
import com.pubmatic.sdk.video.vastmodels.l;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/* loaded from: classes2.dex */
public class n extends FrameLayout implements u, k {
    public static final int MEDIA_CONTROL_VISIBILITY_DELAY = 200;
    private com.pubmatic.sdk.webrendering.ui.o A;
    private InterfaceC4066a B;
    private String C;
    private boolean D;

    @NonNull
    private final com.pubmatic.sdk.video.c E;
    private a F;

    @NonNull
    private final MutableContextWrapper G;
    private boolean H;
    private String I;
    private com.pubmatic.sdk.video.vastparser.b J;
    private int a;

    @NonNull
    private Map<Object, Object> b;

    @NonNull
    private com.pubmatic.sdk.common.network.n c;
    private o d;
    private int e;
    private com.pubmatic.sdk.common.f f;
    private s g;
    private TextView h;
    private ImageButton i;
    private com.pubmatic.sdk.video.vastmodels.j j;
    private String k;
    private boolean l;
    private boolean m;
    private com.pubmatic.sdk.video.a n;
    private boolean o;
    private com.pubmatic.sdk.video.vastmodels.e p;

    @NonNull
    private final View.OnClickListener q;
    private double r;
    private long s;

    @NonNull
    private List<String> t;
    private TextView u;

    @NonNull
    private com.pubmatic.sdk.video.b v;

    @NonNull
    private com.pubmatic.sdk.common.models.f w;
    private com.pubmatic.sdk.video.player.j x;
    private com.pubmatic.sdk.video.vastmodels.b y;
    private C4069d z;

    public enum a {
        LINEAR,
        NON_LINEAR,
        ANY
    }

    public class b implements View.OnClickListener {
        public b() {
        }

        @Override // android.view.View.OnClickListener
        public void onClick(View view) {
            int id = view.getId();
            if (id == com.pubmatic.sdk.video.h.pob_learn_more_btn) {
                n.this.f();
                return;
            }
            if (id == com.pubmatic.sdk.video.h.pob_close_btn) {
                if (n.this.g != null) {
                    if (n.this.g.getPlayerState() != r.ERROR) {
                        if (n.this.d != null) {
                            n.this.d.onSkip();
                            return;
                        }
                        return;
                    } else {
                        if (n.this.d != null) {
                            n.this.d.onClose();
                            return;
                        }
                        return;
                    }
                }
                return;
            }
            if (id != com.pubmatic.sdk.video.h.pob_forward_btn) {
                if (id != com.pubmatic.sdk.video.h.pob_custom_product_close_btn || n.this.d == null) {
                    return;
                }
                n.this.d.onClose();
                return;
            }
            n.this.j();
            if (n.this.g != null) {
                n.this.g.stop();
                n.this.b();
            }
        }
    }

    public class c implements com.pubmatic.sdk.video.vastparser.b {
        public c() {
        }

        @Override // com.pubmatic.sdk.video.vastparser.b
        public void onFailure(com.pubmatic.sdk.video.vastmodels.i iVar, @NonNull com.pubmatic.sdk.video.a aVar) {
            if (iVar == null || iVar.getAds() == null || iVar.getAds().isEmpty()) {
                n.this.a((com.pubmatic.sdk.video.vastmodels.j) null, aVar);
            } else {
                n.this.a(iVar.getAds().get(0), aVar);
            }
        }

        @Override // com.pubmatic.sdk.video.vastparser.b
        public void onSuccess(@NonNull com.pubmatic.sdk.video.vastmodels.i iVar) {
            if (iVar.getAds() == null || iVar.getAds().isEmpty()) {
                return;
            }
            n.this.b(iVar.getAds().get(0));
        }
    }

    public class d implements com.pubmatic.sdk.webrendering.ui.o {
        public d() {
        }

        @Override // com.pubmatic.sdk.webrendering.ui.o
        public void onSkipOptionUpdate(boolean z) {
            n.this.a(z);
        }
    }

    public class g implements Runnable {
        final /* synthetic */ C4069d a;
        final /* synthetic */ com.pubmatic.sdk.video.vastmodels.c b;

        public g(C4069d c4069d, com.pubmatic.sdk.video.vastmodels.c cVar) {
            this.a = c4069d;
            this.b = cVar;
        }

        @Override // java.lang.Runnable
        public void run() {
            if (n.this.z != null) {
                n.this.c(this.a, this.b);
            }
        }
    }

    public class h implements Runnable {
        final /* synthetic */ C4069d a;

        public h(C4069d c4069d) {
            this.a = c4069d;
        }

        @Override // java.lang.Runnable
        public void run() {
            POBLog.debug("POBVastPlayer", "Removing Icon from UI.", new Object[0]);
            n.this.removeView(this.a);
        }
    }

    public class i implements View.OnClickListener {
        public i() {
        }

        @Override // android.view.View.OnClickListener
        public void onClick(@NonNull View view) {
            if (n.this.I != null) {
                n nVar = n.this;
                nVar.a(nVar.I);
                n.this.i();
            }
        }
    }

    public class j implements Runnable {
        final /* synthetic */ int a;

        public j(int i) {
            this.a = i;
        }

        @Override // java.lang.Runnable
        public void run() {
            if (n.this.i != null && n.this.h != null && n.this.D) {
                int i = this.a / 1000;
                if (!n.this.m) {
                    if (n.this.r > i) {
                        n.this.h.setText(String.valueOf(((int) n.this.r) - i));
                    } else if (n.this.r != n.this.s) {
                        n.this.i.setVisibility(0);
                        n.this.m = true;
                        n.this.h.setVisibility(8);
                        if (!n.this.l) {
                            n.this.a(true);
                        }
                    }
                }
            }
            if (n.this.x != null) {
                n.this.x.onProgress(this.a / 1000);
            }
        }
    }

    public n(@NonNull MutableContextWrapper mutableContextWrapper, @NonNull com.pubmatic.sdk.video.c cVar) {
        super(mutableContextWrapper);
        this.a = 0;
        this.e = 3;
        this.l = false;
        this.m = false;
        this.o = true;
        this.q = new b();
        this.D = true;
        this.F = a.ANY;
        this.J = new c();
        this.G = mutableContextWrapper;
        com.pubmatic.sdk.common.network.n trackerHandler = com.pubmatic.sdk.common.i.getTrackerHandler(com.pubmatic.sdk.common.i.getNetworkHandler(mutableContextWrapper));
        this.c = trackerHandler;
        this.v = new com.pubmatic.sdk.video.b(trackerHandler);
        this.E = cVar;
        this.t = new ArrayList();
        this.b = Collections.synchronizedMap(new HashMap(4));
    }

    private int a(int i2) {
        if (i2 == -1) {
            return 402;
        }
        return com.pubmatic.sdk.video.a.MEDIA_FILE_DISPLAY_ERROR;
    }

    @NonNull
    public static n createInstance(@NonNull Context context, @NonNull com.pubmatic.sdk.video.c cVar) {
        return new n(new MutableContextWrapper(context.getApplicationContext()), cVar);
    }

    private com.pubmatic.sdk.video.vastmodels.b getMatchingCompanion() {
        com.pubmatic.sdk.video.vastmodels.j jVar = this.j;
        if (jVar != null) {
            List<com.pubmatic.sdk.video.vastmodels.b> combinedCompanions = jVar.getCombinedCompanions();
            if (combinedCompanions != null && !combinedCompanions.isEmpty()) {
                float width = getWidth();
                float height = getHeight();
                com.pubmatic.sdk.common.f fVar = this.f;
                if (fVar != null) {
                    width = com.pubmatic.sdk.common.utility.o.convertDpToPixelWithFloatPrecession(fVar.getAdWidth());
                    height = com.pubmatic.sdk.common.utility.o.convertDpToPixelWithFloatPrecession(this.f.getAdHeight());
                }
                com.pubmatic.sdk.video.vastmodels.b suitableEndCardCompanion = p.getSuitableEndCardCompanion(combinedCompanions, width, height);
                if (suitableEndCardCompanion == null) {
                    this.n = new com.pubmatic.sdk.video.a(601, "Couldn't find suitable end-card.");
                    return suitableEndCardCompanion;
                }
                POBLog.debug("POBVastPlayer", "Selected end card - " + suitableEndCardCompanion, new Object[0]);
                return suitableEndCardCompanion;
            }
            this.n = new com.pubmatic.sdk.video.a(603, "No companion found as an end-card.");
        }
        return null;
    }

    @NonNull
    private Map<Object, Object> getVASTMacros() {
        this.b.put("[ADCOUNT]", String.valueOf(this.a));
        this.b.put("[CACHEBUSTING]", Integer.valueOf(com.pubmatic.sdk.common.utility.o.getRandomNumber(10000000, 99999999)));
        return this.b;
    }

    public void destroy() {
        POBLog.debug("POBVastPlayer", "Vast player destroy called!", new Object[0]);
        if (!this.t.contains(j.a.IMPRESSIONS.name()) && this.t.contains(l.b.LOADED.name())) {
            a(l.b.NOT_USED);
        } else if (this.D) {
            g();
        }
        s sVar = this.g;
        if (sVar != null) {
            sVar.destroy();
        }
        InterfaceC4066a interfaceC4066a = this.B;
        if (interfaceC4066a != null) {
            interfaceC4066a.setListener(null);
        }
        C4069d c4069d = this.z;
        if (c4069d != null) {
            c4069d.destroy();
            this.z = null;
        }
        removeAllViews();
        this.a = 0;
        this.B = null;
        this.d = null;
        this.J = null;
        this.y = null;
        this.n = null;
    }

    public boolean getSkipabilityEnabled() {
        return this.D;
    }

    @NonNull
    public com.pubmatic.sdk.video.c getVastPlayerConfig() {
        return this.E;
    }

    public void load(@NonNull String str) {
        Trace.beginSection("POB Vast Parsing");
        com.pubmatic.sdk.video.vastparser.a aVar = new com.pubmatic.sdk.video.vastparser.a(com.pubmatic.sdk.common.i.getNetworkHandler(getContext().getApplicationContext()), this.e, this.J);
        aVar.setWrapperTimeout(this.E.getWrapperUriTimeout());
        aVar.parse(str);
    }

    @Override // com.pubmatic.sdk.video.player.u
    public void onBufferUpdate(int i2) {
    }

    @Override // com.pubmatic.sdk.video.player.u
    public void onClick() {
        f();
    }

    @Override // com.pubmatic.sdk.video.player.u
    public void onCompletion() {
        setOnClickListener(null);
        l.b bVar = l.b.COMPLETE;
        a(bVar);
        b(bVar);
        o oVar = this.d;
        if (oVar != null) {
            oVar.onPlaybackCompleted(this.s);
        }
        TextView textView = this.h;
        if (textView != null) {
            textView.setVisibility(8);
        }
        b();
    }

    @Override // com.pubmatic.sdk.video.player.u
    public void onFailure(int i2, @NonNull String str) {
        a(this.j, new com.pubmatic.sdk.video.a(a(i2), str));
        ImageButton imageButton = this.i;
        if (imageButton != null) {
            if (imageButton.getId() == com.pubmatic.sdk.video.h.pob_forward_btn || !this.i.isShown()) {
                TextView textView = this.h;
                if (textView != null) {
                    textView.setVisibility(8);
                }
                com.pubmatic.sdk.webrendering.a.updateSkipButtonToCloseButton(this.i);
                this.i.setVisibility(0);
                this.m = true;
                a(true);
            }
        }
    }

    @Override // com.pubmatic.sdk.video.player.u
    public void onMute(boolean z) {
        if (z) {
            l.b bVar = l.b.MUTE;
            a(bVar);
            b(bVar);
        } else {
            l.b bVar2 = l.b.UNMUTE;
            a(bVar2);
            b(bVar2);
        }
    }

    @Override // com.pubmatic.sdk.video.player.u
    public void onPause() {
        POBLog.debug("POBVastPlayer", "Playback paused.", new Object[0]);
        l.b bVar = l.b.PAUSE;
        a(bVar);
        b(bVar);
    }

    @Override // com.pubmatic.sdk.video.player.k
    public void onProgressReached(@NonNull Map<l.b, List<String>> map) {
        for (Map.Entry<l.b, List<String>> entry : map.entrySet()) {
            l.b key = entry.getKey();
            POBLog.debug("POBVastPlayer", "Event occurred: %s", key.name());
            List<String> value = entry.getValue();
            b(key);
            if (value != null && this.j != null) {
                a(value);
                this.t.add(key.name());
            }
        }
    }

    @Override // com.pubmatic.sdk.video.player.u
    public void onProgressUpdate(int i2) {
        post(new j(i2));
    }

    @Override // com.pubmatic.sdk.video.player.u
    public void onReadyToPlay(@NonNull v vVar) {
        this.a++;
        long mediaDuration = vVar.getMediaDuration() / 1000;
        this.s = mediaDuration;
        if (this.D) {
            this.r = p.getSkipOffset(this.r, this.E, mediaDuration);
            POBLog.debug("POBVastPlayer", "Video skipOffset: " + this.r, new Object[0]);
        }
        POBLog.debug("POBVastPlayer", "Video duration: %s seconds, skip option will be available after %s seconds.", Long.valueOf(this.s), Double.valueOf(this.r));
        Trace.endSection();
        o oVar = this.d;
        if (oVar != null) {
            oVar.onReadyToPlay(this.j, (float) this.r);
        }
        a(l.b.LOADED);
        a(this.s);
        this.y = getMatchingCompanion();
    }

    @Override // com.pubmatic.sdk.video.player.u
    public void onResume() {
        POBLog.debug("POBVastPlayer", "Playback started.", new Object[0]);
        l.b bVar = l.b.RESUME;
        a(bVar);
        b(bVar);
    }

    @Override // com.pubmatic.sdk.video.player.u
    public void onStart() {
        POBLog.debug("POBVastPlayer", "Playback started.", new Object[0]);
        b(true);
        j.a aVar = j.a.IMPRESSIONS;
        if (this.j != null) {
            POBLog.debug("POBVastPlayer", "Event occurred: %s", aVar.name());
            a(this.j.getCombinedList(aVar));
            this.t.add(aVar.name());
            a(l.b.START);
            if (this.d != null && (this.j.getCreative() instanceof com.pubmatic.sdk.video.vastmodels.d)) {
                this.d.onVideoStarted(this.s, this.E.isPlayOnMute() ? DefinitionKt.NO_Float_VALUE : 1.0f);
            }
            l();
        }
    }

    @Override // android.view.View
    public void onWindowVisibilityChanged(int i2) {
        super.onWindowVisibilityChanged(i2);
        if (30 == Build.VERSION.SDK_INT && i2 == 0) {
            bringToFront();
        }
    }

    public void pause() {
        s sVar = this.g;
        if (sVar == null || sVar.getPlayerState() != r.PLAYING || this.g.getPlayerState() == r.STOPPED) {
            return;
        }
        this.g.pause();
    }

    public void play() {
        s sVar = this.g;
        if (sVar != null) {
            if ((sVar.getPlayerState() != r.PAUSED && this.g.getPlayerState() != r.LOADED) || this.g.getPlayerState() == r.STOPPED || this.g.getPlayerState() == r.COMPLETE) {
                return;
            }
            this.g.play();
        }
    }

    public void setAutoPlayOnForeground(boolean z) {
        s sVar = this.g;
        if (sVar != null) {
            sVar.setAutoPlayOnForeground(z);
        }
    }

    public void setBaseContext(@NonNull Context context) {
        this.G.setBaseContext(context);
    }

    public void setBidBundleId(String str) {
        this.k = str;
    }

    public void setDeviceInfo(@NonNull com.pubmatic.sdk.common.models.f fVar) {
        this.w = fVar;
    }

    public void setEnableLearnMoreButton(boolean z) {
        this.o = z;
    }

    public void setEndCardSize(com.pubmatic.sdk.common.f fVar) {
        this.f = fVar;
    }

    public void setFSCEnabled(boolean z) {
        this.H = z;
    }

    public void setLinearity(a aVar) {
        this.F = aVar;
    }

    public void setMaxWrapperThreshold(int i2) {
        this.e = i2;
    }

    public void setOnSkipOptionUpdateListener(com.pubmatic.sdk.webrendering.ui.o oVar) {
        this.A = oVar;
    }

    public void setPlacementType(@NonNull String str) {
        this.C = str;
    }

    public void setShowEndCardOnSkip(boolean z) {
        this.l = z;
    }

    public void setSkipabilityEnabled(boolean z) {
        this.D = z;
    }

    public void setVastPlayerListener(o oVar) {
        this.d = oVar;
    }

    public class e implements w {
        public e() {
        }

        @Override // com.pubmatic.sdk.video.player.w
        public void a() {
            if (n.this.y != null) {
                n nVar = n.this;
                nVar.a(nVar.y.getTrackingEventUrls(l.b.CREATIVE_VIEW));
            }
        }

        @Override // com.pubmatic.sdk.video.player.w
        public void b() {
            n.this.f();
        }

        @Override // com.pubmatic.sdk.video.player.w
        public void c() {
            if (n.this.y == null) {
                n.this.f();
                return;
            }
            if (com.pubmatic.sdk.common.utility.o.isNullOrEmpty(n.this.y.getClickThroughURL())) {
                POBLog.debug("POBVastPlayer", "Click through URL is not available in matching companion.", new Object[0]);
                n nVar = n.this;
                nVar.a(nVar.j);
            } else {
                n nVar2 = n.this;
                nVar2.a(nVar2.y.getClickThroughURL());
            }
            List<String> clickTrackers = n.this.y.getClickTrackers();
            if (clickTrackers != null && !clickTrackers.isEmpty()) {
                n.this.a(clickTrackers);
            } else {
                POBLog.debug("POBVastPlayer", "Click trackers are not available in matching companion.", new Object[0]);
                n.this.i();
            }
        }

        @Override // com.pubmatic.sdk.video.player.w
        public void d() {
            n.this.m();
            n.this.a();
        }

        @Override // com.pubmatic.sdk.video.player.w
        public void onClose() {
            if (n.this.d != null) {
                n.this.d.onClose();
            }
        }

        @Override // com.pubmatic.sdk.video.player.w
        public void onEndCardWillLeaveApp() {
            n.this.h();
        }

        @Override // com.pubmatic.sdk.video.player.w
        public void a(String str, boolean z) {
            List<String> clickTrackers;
            if (n.this.y != null && (clickTrackers = n.this.y.getClickTrackers()) != null) {
                n.this.a(clickTrackers);
            }
            if (z) {
                n.this.k();
            } else {
                n.this.a(str);
            }
        }

        @Override // com.pubmatic.sdk.video.player.w
        public void a(@NonNull com.pubmatic.sdk.video.a aVar) {
            n nVar = n.this;
            nVar.a(nVar.j, aVar);
        }
    }

    private void c() {
        if (this.l) {
            this.i = com.pubmatic.sdk.webrendering.a.createSkipButton(getContext(), com.pubmatic.sdk.video.h.pob_forward_btn, com.pubmatic.sdk.video.g.pob_ic_forward_24);
        } else {
            this.i = com.pubmatic.sdk.webrendering.a.createSkipButton(getContext(), com.pubmatic.sdk.video.h.pob_close_btn, com.pubmatic.sdk.video.g.pob_ic_close_black_24dp);
        }
        this.i.setVisibility(8);
        this.m = false;
        this.i.setOnClickListener(this.q);
        addView(this.i);
    }

    private void d() {
        TextView textViewCreateSkipDurationTextView = com.pubmatic.sdk.webrendering.a.createSkipDurationTextView(getContext(), com.pubmatic.sdk.video.h.pob_skip_duration_timer);
        this.h = textViewCreateSkipDurationTextView;
        addView(textViewCreateSkipDurationTextView, com.pubmatic.sdk.webrendering.a.getLayoutParamsForTopRightPosition(getContext()));
    }

    private void e() {
        if (this.D) {
            d();
            c();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void f() {
        a(this.j);
        i();
    }

    private void g() {
        s sVar;
        List<String> list = this.t;
        l.b bVar = l.b.CLOSE_LINEAR;
        if (list.contains(bVar.name())) {
            return;
        }
        List<String> list2 = this.t;
        l.b bVar2 = l.b.CLOSE;
        if (list2.contains(bVar2.name()) || this.j == null || (sVar = this.g) == null) {
            return;
        }
        if (!this.l && sVar.getPlayerState() != r.COMPLETE) {
            j();
        }
        if (this.j.getCombinedTrackingEventList(bVar).isEmpty()) {
            a(bVar2);
        } else {
            a(bVar);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void h() {
        o oVar = this.d;
        if (oVar != null) {
            oVar.onEndCardWillLeaveApp();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void i() {
        if (this.j != null) {
            j.a aVar = j.a.CLICKTRACKING;
            POBLog.debug("POBVastPlayer", "Event occurred: %s", aVar.name());
            List<String> combinedList = this.j.getCombinedList(aVar);
            if (combinedList.isEmpty()) {
                POBLog.debug("POBVastPlayer", "Empty click tracker URL list found at click event. Skipping tracker execution.", new Object[0]);
            } else {
                a(combinedList);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void j() {
        l.b bVar = l.b.SKIP;
        b(bVar);
        a(bVar);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void k() {
        o oVar = this.d;
        if (oVar != null) {
            oVar.shouldForwardClickEvent();
        }
    }

    private void l() {
        com.pubmatic.sdk.video.vastmodels.j jVar = this.j;
        if (jVar != null) {
            a(jVar.getClosestIcon());
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void m() {
        com.pubmatic.sdk.webrendering.ui.f fVar = new com.pubmatic.sdk.webrendering.ui.f(this.G.getBaseContext());
        fVar.setInstallButtonClickListener(new i());
        addView(fVar);
    }

    private void n() {
        s sVar = this.g;
        if (sVar != null) {
            sVar.setPrepareTimeout(this.E.getMediaUriTimeout());
            this.g.playOnMute(this.E.isPlayOnMute());
        }
    }

    public class f implements m {
        final /* synthetic */ com.pubmatic.sdk.video.vastmodels.c a;

        public f(com.pubmatic.sdk.video.vastmodels.c cVar) {
            this.a = cVar;
        }

        @Override // com.pubmatic.sdk.video.player.m
        public void a() {
            POBLog.debug("POBVastPlayer", "Icon loaded.", new Object[0]);
            if (n.this.z != null) {
                n nVar = n.this;
                nVar.b(nVar.z, this.a);
            }
        }

        @Override // com.pubmatic.sdk.video.player.m
        public void a(String str) {
            POBLog.debug("POBVastPlayer", "Icon clicked.", new Object[0]);
            List<String> clickTrackers = this.a.getClickTrackers();
            if (clickTrackers != null) {
                n.this.a(clickTrackers);
            }
            POBLog.debug("POBVastPlayer", "Opening landing page of icon with url: %s", str);
            if (n.this.d != null) {
                n.this.d.onIndustryIconClick(str);
            }
        }

        @Override // com.pubmatic.sdk.video.player.m
        public void a(@NonNull com.pubmatic.sdk.video.a aVar) {
            POBLog.debug("POBVastPlayer", "Unable to render Icon due to invalid details.", new Object[0]);
        }
    }

    private void b(l.b bVar) {
        o oVar = this.d;
        if (oVar != null) {
            oVar.onVideoEventOccurred(bVar);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void b(@NonNull com.pubmatic.sdk.video.vastmodels.j jVar) {
        com.pubmatic.sdk.video.a aVar;
        a aVar2;
        POBLog.debug("POBVastPlayer", "Vast player started rendering.", new Object[0]);
        this.j = jVar;
        this.b.put("[ADSERVINGID]", jVar.getAdServingId());
        this.b.put("[PODSEQUENCE]", String.valueOf(this.j.getAdSequence()));
        this.t = new ArrayList();
        com.pubmatic.sdk.video.vastmodels.l creative = jVar.getCreative();
        if (creative != null) {
            if (creative.getVastCreativeType() == l.a.LINEAR && ((aVar2 = this.F) == a.LINEAR || aVar2 == a.ANY)) {
                a((com.pubmatic.sdk.video.vastmodels.d) creative);
                aVar = null;
            } else {
                aVar = new com.pubmatic.sdk.video.a(201, "Expected linearity not found.");
            }
        } else {
            aVar = new com.pubmatic.sdk.video.a(400, "No ad creative found.");
        }
        if (aVar != null) {
            a(this.j, aVar);
        }
    }

    private void a(@NonNull l.b bVar) {
        if (this.j != null) {
            POBLog.debug("POBVastPlayer", "Event occurred: %s", bVar.name());
            a(this.j.getCombinedTrackingEventList(bVar));
            this.t.add(bVar.name());
            return;
        }
        POBLog.debug("POBVastPlayer", "Selected Vast Ad is null", new Object[0]);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void c(@NonNull C4069d c4069d, @NonNull com.pubmatic.sdk.video.vastmodels.c cVar) {
        long duration = cVar.getDuration() * 1000;
        if (duration > 0) {
            new Handler().postDelayed(new h(c4069d), duration);
        }
        a(c4069d, cVar);
        List<String> viewTrackers = cVar.getViewTrackers();
        if (viewTrackers != null) {
            a(viewTrackers);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void a(@NonNull List<String> list) {
        this.c.sendTrackers(com.pubmatic.sdk.common.network.n.sanitizeURLScheme(list, com.pubmatic.sdk.common.i.getSdkConfig().isRequestSecureCreative()), getVASTMacros());
    }

    private void a(@NonNull com.pubmatic.sdk.video.vastmodels.d dVar) {
        com.pubmatic.sdk.video.a aVar;
        List<com.pubmatic.sdk.video.vastmodels.e> mediaFiles = dVar.getMediaFiles();
        if (mediaFiles != null && !mediaFiles.isEmpty()) {
            this.r = dVar.getSkipOffset();
            boolean zIsWiFiConnected = com.pubmatic.sdk.common.i.getNetworkMonitor(getContext().getApplicationContext()).isWiFiConnected();
            int scaleFactor = p.getScaleFactor(getContext().getApplicationContext());
            int bitRate = p.getBitRate(scaleFactor == 1, zIsWiFiConnected);
            POBLog.info("POBVastPlayer", "Expected bitrate for %s resolution & %s network is %d", scaleFactor == 1 ? "low" : "high", zIsWiFiConnected ? "wifi" : "non-wifi", Integer.valueOf(bitRate));
            q[] qVarArr = s.SUPPORTED_MEDIA_TYPE;
            com.pubmatic.sdk.common.models.f fVar = this.w;
            com.pubmatic.sdk.video.vastmodels.e eVarFilterMediaFiles = p.filterMediaFiles(mediaFiles, qVarArr, bitRate, fVar.screenWidth, fVar.screenHeight);
            this.p = eVarFilterMediaFiles;
            if (eVarFilterMediaFiles != null) {
                POBLog.info("POBVastPlayer", "Selected media file: %s from media files: %s, for bitrate: %d & size: %s & supported mimes: %s", eVarFilterMediaFiles.toString(), mediaFiles.toString(), Integer.valueOf(bitRate), this.p.getWidth() + "x" + this.p.getHeight(), Arrays.toString(qVarArr));
                String mediaFileURL = this.p.getMediaFileURL();
                POBLog.debug("POBVastPlayer", "Selected media file: %s", mediaFileURL);
                this.g = a(getContext());
                n();
                e();
                if (mediaFileURL != null) {
                    Trace.endSection();
                    Trace.beginSection("POB Rendering");
                    this.g.load(mediaFileURL);
                    aVar = null;
                } else {
                    aVar = new com.pubmatic.sdk.video.a(403, "No supported media file found for linear ad.");
                }
                b(false);
            } else {
                aVar = new com.pubmatic.sdk.video.a(403, "No supported media file found for linear ad.");
            }
        } else {
            aVar = new com.pubmatic.sdk.video.a(401, "Media file not found for linear ad.");
        }
        if (aVar != null) {
            a(this.j, aVar);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void b() {
        com.pubmatic.sdk.video.a aVar;
        POBLog.debug("POBVastPlayer", "Rendering end-card.", new Object[0]);
        if (DTBAdSize.AAX_INTERSTITIAL_AD_SIZE.equals(this.C)) {
            this.I = p.getCustomProductPageClickUrl(this.j, this.k);
            ViewOnClickListenerC4071f viewOnClickListenerC4071f = new ViewOnClickListenerC4071f(this.G.getBaseContext(), !com.pubmatic.sdk.common.utility.o.isNullOrEmpty(this.I));
            this.B = viewOnClickListenerC4071f;
            viewOnClickListenerC4071f.setFSCEnabled(this.H);
            this.B.setSkipAfter(this.E.getEndCardSkipAfter());
            this.B.setOnSkipOptionUpdateListener(new d());
        } else {
            ViewOnClickListenerC4068c viewOnClickListenerC4068c = new ViewOnClickListenerC4068c(getContext());
            this.B = viewOnClickListenerC4068c;
            viewOnClickListenerC4068c.setFSCEnabled(this.H);
        }
        this.B.setLearnMoreTitle(com.pubmatic.sdk.webrendering.a.getLocalizedStringForKey(getContext(), "openwrap_learn_more_title", "Learn More"));
        this.B.setListener(new e());
        com.pubmatic.sdk.video.vastmodels.j jVar = this.j;
        if (jVar != null) {
            if (this.y == null && (aVar = this.n) != null) {
                a(jVar, aVar);
            }
            this.B.render(this.y);
            addView(this.B.getView());
            b(false);
            ImageButton imageButton = this.i;
            if (imageButton != null) {
                removeView(imageButton);
            }
            C4069d c4069d = this.z;
            if (c4069d != null) {
                c4069d.bringToFront();
            }
        }
    }

    private void b(boolean z) {
        s sVar = this.g;
        if (sVar != null) {
            com.pubmatic.sdk.video.player.i controllerView = sVar.getControllerView();
            if (controllerView != null) {
                if (z) {
                    F.b(controllerView, 200);
                } else {
                    F.a(controllerView, 200);
                }
            }
            TextView textView = this.u;
            if (textView != null) {
                if (z) {
                    F.b(textView, 200);
                } else {
                    F.a(textView, 200);
                }
            }
        }
    }

    @NonNull
    private v a(@NonNull Context context) {
        v vVar = new v(context);
        vVar.setListener(this);
        vVar.setFSCEnabled(this.H);
        com.pubmatic.sdk.video.player.i tVar = new t(context);
        FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(-1, -1);
        layoutParams.gravity = 80;
        vVar.setControllerView(tVar, layoutParams);
        FrameLayout.LayoutParams layoutParams2 = new FrameLayout.LayoutParams(-1, -1);
        layoutParams2.gravity = 17;
        addView(vVar, layoutParams2);
        a(vVar);
        return vVar;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void b(@NonNull C4069d c4069d, @NonNull com.pubmatic.sdk.video.vastmodels.c cVar) {
        new Handler().postDelayed(new g(c4069d, cVar), cVar.getOffset() * 1000);
    }

    private void a(@NonNull v vVar) {
        if (this.o) {
            TextView textViewA = F.a(getContext(), com.pubmatic.sdk.video.h.pob_learn_more_btn, com.pubmatic.sdk.webrendering.a.getLocalizedStringForKey(getContext(), "openwrap_learn_more_title", "Learn More"), getResources().getColor(com.pubmatic.sdk.video.e.pob_controls_background_color));
            this.u = textViewA;
            textViewA.setOnClickListener(this.q);
            vVar.addView(this.u);
        }
    }

    private void a(long j2) {
        this.x = new com.pubmatic.sdk.video.player.j(this);
        a(((int) (25 * j2)) / 100, l.b.FIRST_QUARTILE);
        a(((int) (50 * j2)) / 100, l.b.MID_POINT);
        a(((int) (75 * j2)) / 100, l.b.THIRD_QUARTILE);
        com.pubmatic.sdk.video.vastmodels.j jVar = this.j;
        if (jVar != null) {
            for (com.pubmatic.sdk.video.xmlserialiser.b bVar : jVar.getCombinedObjectList(j.a.PROGRESS_TRACKING_EVENT)) {
                if (bVar instanceof com.pubmatic.sdk.video.vastmodels.h) {
                    com.pubmatic.sdk.video.vastmodels.h hVar = (com.pubmatic.sdk.video.vastmodels.h) bVar;
                    ArrayList arrayList = new ArrayList();
                    arrayList.add(hVar.getUrl());
                    this.x.addProgressUrls(Integer.valueOf((int) com.pubmatic.sdk.common.utility.o.convertToSeconds(String.valueOf(j2), hVar.getOffset())), l.b.PROGRESS, arrayList);
                }
            }
        }
    }

    private void a(int i2, @NonNull l.b bVar) {
        com.pubmatic.sdk.video.vastmodels.j jVar = this.j;
        if (jVar == null || this.x == null) {
            return;
        }
        this.x.addProgressUrls(Integer.valueOf(i2), bVar, jVar.getCombinedTrackingEventList(bVar));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void a(com.pubmatic.sdk.video.vastmodels.j jVar, @NonNull com.pubmatic.sdk.video.a aVar) {
        if (jVar != null) {
            this.v.executeVastErrorsWithMacros(jVar.getCombinedList(j.a.ERRORS), getVASTMacros(), aVar, p.generateErrorQueryParams(getContext(), this.w, this.p));
        } else {
            this.v.executeVastErrors(null, aVar);
        }
        Trace.endSection();
        com.pubmatic.sdk.common.h hVarConvertToPOBError = com.pubmatic.sdk.video.b.convertToPOBError(aVar);
        if (hVarConvertToPOBError != null) {
            a(hVarConvertToPOBError);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void a(boolean z) {
        com.pubmatic.sdk.webrendering.ui.o oVar = this.A;
        if (oVar != null) {
            oVar.onSkipOptionUpdate(z);
        }
    }

    private void a(@NonNull com.pubmatic.sdk.common.h hVar) {
        POBLog.error("POBVastPlayer", hVar.toString(), new Object[0]);
        o oVar = this.d;
        if (oVar != null) {
            oVar.onFailedToPlay(hVar);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void a(com.pubmatic.sdk.video.vastmodels.j jVar) {
        if (jVar != null) {
            a(jVar.getClosestClickThroughURL());
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void a(String str) {
        o oVar = this.d;
        if (oVar != null) {
            oVar.onOpenLandingPage(str);
        }
    }

    private void a(com.pubmatic.sdk.video.vastmodels.c cVar) {
        if (cVar != null && cVar.getResource() != null && cVar.getOffset() <= this.s) {
            POBLog.debug("POBVastPlayer", "Rendering icon for program %s after offset %s for duration %s", cVar.getProgram(), Integer.valueOf(cVar.getOffset()), Integer.valueOf(cVar.getDuration()));
            C4069d c4069d = new C4069d(getContext());
            this.z = c4069d;
            c4069d.setId(com.pubmatic.sdk.video.h.pob_industry_icon_one);
            this.z.setListener(new f(cVar));
            this.z.a(cVar);
            return;
        }
        POBLog.debug("POBVastPlayer", "Icon resource is unavailable.", new Object[0]);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void a() {
        InterfaceC4066a interfaceC4066a = this.B;
        if (interfaceC4066a != null && interfaceC4066a.getView().getParent() == this) {
            removeView(this.B.getView());
        }
        ImageButton imageButton = this.i;
        if (imageButton != null) {
            com.pubmatic.sdk.webrendering.a.updateSkipButtonToCloseButton(imageButton);
            this.i.setId(com.pubmatic.sdk.video.h.pob_custom_product_close_btn);
            addView(this.i);
            this.i.setVisibility(0);
            this.i.bringToFront();
        }
    }

    private void a(@NonNull C4069d c4069d, @NonNull com.pubmatic.sdk.video.vastmodels.c cVar) {
        addView(c4069d, F.a(getContext(), cVar.getContentWidth(), cVar.getContentHeight()));
    }
}
