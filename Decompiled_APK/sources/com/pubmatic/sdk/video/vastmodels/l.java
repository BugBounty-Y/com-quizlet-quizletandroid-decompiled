package com.pubmatic.sdk.video.vastmodels;

import androidx.annotation.NonNull;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/* loaded from: classes2.dex */
public abstract class l implements com.pubmatic.sdk.video.xmlserialiser.b {
    protected String mClickThroughURL;
    protected List<String> mClickTrackers;

    public enum a {
        LINEAR,
        NONLINEAR,
        COMPANION
    }

    public enum b {
        CREATIVE_VIEW("creativeview"),
        START("start"),
        FIRST_QUARTILE("firstquartile"),
        MID_POINT("midpoint"),
        THIRD_QUARTILE("thirdQuartile"),
        COMPLETE("complete"),
        MUTE("mute"),
        UNMUTE("unmute"),
        PAUSE("pause"),
        REWIND("rewind"),
        RESUME("resume"),
        FULL_SCREEN("fullscreen"),
        EXIT_FULL_SCREEN("exitFullscreen"),
        EXPAND("expand"),
        COLLAPSE("collapse"),
        ACCEPT_INVITATION_LINEAR("acceptInvitationLinear"),
        CLOSE_LINEAR("closeLinear"),
        SKIP("skip"),
        PROGRESS("progress"),
        AD_EXPAND("adExpand"),
        AD_COLLAPSE("adCollapse"),
        MINIMIZE("minimize"),
        OVERLAY_VIEW_DURATION("overlayViewDuration"),
        CLOSE("close"),
        OTHER_AD_INTERACTION("otherAdInteraction"),
        LOADED("loaded"),
        PLAYER_EXPAND("playerExpand"),
        PLAYER_COLLAPSE("playerCollapse"),
        NOT_USED("notUsed");

        private final String b;

        b(String str) {
            this.b = str;
        }

        public String getValue() {
            return this.b;
        }
    }

    @Override // com.pubmatic.sdk.video.xmlserialiser.b
    public abstract /* synthetic */ void build(@NonNull com.pubmatic.sdk.video.xmlserialiser.a aVar);

    public String getClickThroughURL() {
        return this.mClickThroughURL;
    }

    public List<String> getClickTrackers() {
        return this.mClickTrackers;
    }

    @NonNull
    public List<String> getTrackingEventUrls(@NonNull b bVar) {
        ArrayList arrayList = new ArrayList();
        List<h> trackingEvents = getTrackingEvents(bVar);
        if (trackingEvents != null) {
            Iterator<h> it2 = trackingEvents.iterator();
            while (it2.hasNext()) {
                arrayList.add(it2.next().getUrl());
            }
        }
        return arrayList;
    }

    public abstract List<h> getTrackingEvents();

    public List<h> getTrackingEvents(@NonNull b bVar) {
        ArrayList arrayList = new ArrayList();
        List<h> trackingEvents = getTrackingEvents();
        if (trackingEvents != null) {
            for (h hVar : trackingEvents) {
                if (hVar.getEvent() != null && hVar.getEvent().equalsIgnoreCase(bVar.getValue())) {
                    arrayList.add(hVar);
                }
            }
        }
        return arrayList;
    }

    public abstract a getVastCreativeType();
}
