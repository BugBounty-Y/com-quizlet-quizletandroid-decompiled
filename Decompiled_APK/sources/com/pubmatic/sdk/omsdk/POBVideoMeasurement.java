package com.pubmatic.sdk.omsdk;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import androidx.annotation.Keep;
import androidx.annotation.NonNull;
import com.iab.omid.library.pubmatic.Omid;
import com.iab.omid.library.pubmatic.adsession.AdEvents;
import com.iab.omid.library.pubmatic.adsession.AdSession;
import com.iab.omid.library.pubmatic.adsession.AdSessionConfiguration;
import com.iab.omid.library.pubmatic.adsession.AdSessionContext;
import com.iab.omid.library.pubmatic.adsession.CreativeType;
import com.iab.omid.library.pubmatic.adsession.ErrorType;
import com.iab.omid.library.pubmatic.adsession.ImpressionType;
import com.iab.omid.library.pubmatic.adsession.Owner;
import com.iab.omid.library.pubmatic.adsession.Partner;
import com.iab.omid.library.pubmatic.adsession.VerificationScriptResource;
import com.iab.omid.library.pubmatic.adsession.media.InteractionType;
import com.iab.omid.library.pubmatic.adsession.media.MediaEvents;
import com.iab.omid.library.pubmatic.adsession.media.PlayerState;
import com.iab.omid.library.pubmatic.adsession.media.Position;
import com.iab.omid.library.pubmatic.adsession.media.VastProperties;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.common.viewability.j;
import com.pubmatic.sdk.common.viewability.k;
import com.pubmatic.sdk.common.viewability.l;
import com.pubmatic.sdk.common.viewability.m;
import com.pubmatic.sdk.common.viewability.n;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.List;

@Keep
/* loaded from: classes2.dex */
public class POBVideoMeasurement extends b implements n {

    @NonNull
    private Handler handler = new Handler(Looper.getMainLooper());
    private MediaEvents mediaEvents;

    public class a implements com.pubmatic.sdk.common.viewability.c {
        final /* synthetic */ List a;
        final /* synthetic */ View b;
        final /* synthetic */ k c;

        public a(List list, View view, k kVar) {
            this.a = list;
            this.b = view;
            this.c = kVar;
        }

        @Override // com.pubmatic.sdk.common.viewability.c
        public void onMeasurementScriptReceived(@NonNull String str) {
            AdSessionContext adSessionContextCreateNativeAdSessionContext = AdSessionContext.createNativeAdSessionContext(Partner.createPartner("Pubmatic", "3.7.0"), str, this.a, null, "");
            Owner owner = Owner.NATIVE;
            AdSessionConfiguration adSessionConfigurationCreateAdSessionConfiguration = AdSessionConfiguration.createAdSessionConfiguration(CreativeType.VIDEO, ImpressionType.ONE_PIXEL, owner, owner, false);
            POBVideoMeasurement.this.adSession = AdSession.createAdSession(adSessionConfigurationCreateAdSessionConfiguration, adSessionContextCreateNativeAdSessionContext);
            POBVideoMeasurement pOBVideoMeasurement = POBVideoMeasurement.this;
            pOBVideoMeasurement.adEvents = AdEvents.createAdEvents(pOBVideoMeasurement.adSession);
            POBVideoMeasurement pOBVideoMeasurement2 = POBVideoMeasurement.this;
            pOBVideoMeasurement2.mediaEvents = MediaEvents.createMediaEvents(pOBVideoMeasurement2.adSession);
            POBVideoMeasurement.this.setTrackView(this.b);
            POBVideoMeasurement.this.handler.post(new g(this));
        }
    }

    @Override // com.pubmatic.sdk.omsdk.b, com.pubmatic.sdk.common.viewability.d
    public void finishAdSession() {
        super.finishAdSession();
        this.adEvents = null;
        this.mediaEvents = null;
    }

    @Override // com.pubmatic.sdk.common.viewability.n
    public void impressionOccurred() {
        if (this.adEvents == null) {
            POBLog.error(d.TAG, "Unable to signal event : %s", "IMPRESSION");
            return;
        }
        try {
            POBLog.info(d.TAG, "Signaling event : %s", "IMPRESSION");
            this.adEvents.impressionOccurred();
        } catch (Exception e) {
            POBLog.error(d.TAG, "Unable to signal event : %s Exception : %s", "IMPRESSION", e.getMessage());
        }
    }

    @Override // com.pubmatic.sdk.common.viewability.n
    public void loaded(boolean z, float f) {
        if (this.adEvents == null) {
            POBLog.error(d.TAG, "Unable to signal event : %s", "LOADED");
            return;
        }
        try {
            POBLog.info(d.TAG, "Signaling event : %s", "LOADED");
            this.adEvents.loaded(z ? VastProperties.createVastPropertiesForSkippableMedia(f, true, Position.STANDALONE) : VastProperties.createVastPropertiesForNonSkippableMedia(true, Position.STANDALONE));
        } catch (Exception e) {
            POBLog.error(d.TAG, "Unable to signal event : %s Exception : %s", "LOADED", e.getMessage());
        }
    }

    @Override // com.pubmatic.sdk.common.viewability.n
    public void signalAdEvent(@NonNull com.pubmatic.sdk.common.g gVar) {
        if (this.mediaEvents == null) {
            POBLog.error(d.TAG, "Unable to signal event : %s", gVar.name());
            return;
        }
        try {
            POBLog.info(d.TAG, "Signaling event : %s", gVar.name());
            switch (e.a[gVar.ordinal()]) {
                case 1:
                    this.mediaEvents.firstQuartile();
                    break;
                case 2:
                    this.mediaEvents.midpoint();
                    break;
                case 3:
                    this.mediaEvents.thirdQuartile();
                    break;
                case 4:
                    this.mediaEvents.complete();
                    break;
                case 5:
                    this.mediaEvents.skipped();
                    break;
                case 6:
                    this.mediaEvents.volumeChange(DefinitionKt.NO_Float_VALUE);
                    break;
                case 7:
                    this.mediaEvents.volumeChange(1.0f);
                    break;
                case 8:
                    this.mediaEvents.adUserInteraction(InteractionType.CLICK);
                    break;
                case 9:
                    this.mediaEvents.pause();
                    break;
                case 10:
                    this.mediaEvents.resume();
                    break;
                case 11:
                    this.mediaEvents.adUserInteraction(InteractionType.INVITATION_ACCEPTED);
                    break;
            }
        } catch (Exception e) {
            POBLog.error(d.TAG, "Unable to signal event : %s Exception : %s", gVar.name(), e.getMessage());
        }
    }

    @Override // com.pubmatic.sdk.common.viewability.n
    public void signalError(@NonNull l lVar, @NonNull String str) {
        if (this.adSession == null) {
            POBLog.error(d.TAG, "Unable to signal error : %s", lVar.name());
            return;
        }
        int i = e.c[lVar.ordinal()];
        if (i == 1) {
            this.adSession.error(ErrorType.GENERIC, str);
        } else {
            if (i != 2) {
                return;
            }
            this.adSession.error(ErrorType.VIDEO, str);
        }
    }

    @Override // com.pubmatic.sdk.common.viewability.n
    public void signalPlayerStateChange(@NonNull m mVar) {
        if (this.mediaEvents == null) {
            POBLog.error(d.TAG, "Unable to signal player state event : %s", mVar.name());
            return;
        }
        try {
            POBLog.info(d.TAG, "Signaling event : %s", mVar.name());
            int i = e.b[mVar.ordinal()];
            if (i == 1) {
                this.mediaEvents.playerStateChange(PlayerState.FULLSCREEN);
                return;
            }
            if (i == 2) {
                this.mediaEvents.playerStateChange(PlayerState.COLLAPSED);
                return;
            }
            if (i == 3) {
                this.mediaEvents.playerStateChange(PlayerState.EXPANDED);
            } else if (i == 4) {
                this.mediaEvents.playerStateChange(PlayerState.MINIMIZED);
            } else {
                if (i != 5) {
                    return;
                }
                this.mediaEvents.playerStateChange(PlayerState.NORMAL);
            }
        } catch (Exception e) {
            POBLog.error(d.TAG, "Unable to signal player state event : %s Exception : %s", mVar.name(), e.getMessage());
        }
    }

    @Override // com.pubmatic.sdk.common.viewability.n
    public void start(float f, float f2) {
        if (this.mediaEvents == null) {
            POBLog.error(d.TAG, "Unable to signal event : %s", "START");
            return;
        }
        try {
            POBLog.info(d.TAG, "Signaling event : %s", "START");
            this.mediaEvents.start(f, f2);
        } catch (Exception e) {
            POBLog.error(d.TAG, "Unable to signal event : %s Exception : %s", "START", e.getMessage());
        }
    }

    @Override // com.pubmatic.sdk.common.viewability.n
    public void startAdSession(@NonNull View view, List<j> list, @NonNull k kVar) {
        try {
            List<VerificationScriptResource> verificationScriptResourceList = d.getVerificationScriptResourceList(list);
            if (verificationScriptResourceList.isEmpty()) {
                POBLog.error(d.TAG, "Unable to start session : %s", "Verification list is empty");
                return;
            }
            Context applicationContext = view.getContext().getApplicationContext();
            if (!Omid.isActive()) {
                Omid.activate(applicationContext);
            }
            omidJsServiceScript(applicationContext, new a(verificationScriptResourceList, view, kVar));
        } catch (Exception e) {
            POBLog.error(d.TAG, "Unable to start session : %s", e.getMessage());
        }
    }
}
