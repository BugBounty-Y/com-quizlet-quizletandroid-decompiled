package com.pubmatic.sdk.omsdk;

import android.content.Context;
import android.view.View;
import androidx.annotation.NonNull;
import com.iab.omid.library.pubmatic.Omid;
import com.iab.omid.library.pubmatic.adsession.AdEvents;
import com.iab.omid.library.pubmatic.adsession.AdSession;
import com.iab.omid.library.pubmatic.adsession.FriendlyObstructionPurpose;
import com.pubmatic.sdk.common.i;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.common.viewability.h;

/* loaded from: classes2.dex */
public abstract class b implements com.pubmatic.sdk.common.viewability.d {
    protected static final String TAG = "OMSDK";
    protected AdEvents adEvents;
    protected AdSession adSession;

    @Override // com.pubmatic.sdk.common.viewability.d, com.pubmatic.sdk.common.viewability.i
    public void addFriendlyObstructions(@NonNull View view, @NonNull h hVar) {
        AdSession adSession = this.adSession;
        if (adSession == null) {
            POBLog.error("OMSDK", "Unable to add obstruction", new Object[0]);
            return;
        }
        try {
            adSession.addFriendlyObstruction(view, FriendlyObstructionPurpose.valueOf(hVar.name()), null);
        } catch (Exception e) {
            POBLog.error("OMSDK", "Unable to add obstruction: %s", e.getMessage());
        }
    }

    @Override // com.pubmatic.sdk.common.viewability.d
    public void finishAdSession() {
        try {
            AdSession adSession = this.adSession;
            if (adSession == null) {
                POBLog.error("OMSDK", "Unable to finish Ad session", new Object[0]);
                return;
            }
            adSession.removeAllFriendlyObstructions();
            this.adSession.finish();
            POBLog.debug("OMSDK", "Ad session finished id : %s", this.adSession.getAdSessionId());
            this.adSession = null;
        } catch (Exception e) {
            POBLog.error("OMSDK", "Unable to finish Ad session: %s", e.getMessage());
        }
    }

    @Override // com.pubmatic.sdk.common.viewability.d
    @NonNull
    public String omSDKVersion() {
        return Omid.getVersion();
    }

    @Override // com.pubmatic.sdk.common.viewability.d
    public void omidJsServiceScript(@NonNull Context context, @NonNull com.pubmatic.sdk.common.viewability.c cVar) {
        i.getCacheManager(context).loadInternalServiceJS(cVar);
    }

    @Override // com.pubmatic.sdk.common.viewability.d, com.pubmatic.sdk.common.viewability.i
    public void removeFriendlyObstructions(View view) {
        AdSession adSession = this.adSession;
        if (adSession == null) {
            POBLog.error("OMSDK", "Unable to remove obstruction", new Object[0]);
            return;
        }
        try {
            if (view != null) {
                adSession.removeFriendlyObstruction(view);
            } else {
                adSession.removeAllFriendlyObstructions();
            }
        } catch (Exception e) {
            POBLog.error("OMSDK", "Unable to add obstruction: %s", e.getMessage());
        }
    }

    @Override // com.pubmatic.sdk.common.viewability.d
    public void setTrackView(@NonNull View view) {
        try {
            if (this.adSession == null) {
                POBLog.error("OMSDK", "Unable to change track view", new Object[0]);
            } else {
                POBLog.debug("OMSDK", "Track view changed", new Object[0]);
                this.adSession.registerAdView(view);
            }
        } catch (Exception e) {
            POBLog.error("OMSDK", "Unable to change track view: %s", e.getMessage());
        }
    }
}
