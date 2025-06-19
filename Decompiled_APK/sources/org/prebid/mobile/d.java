package org.prebid.mobile;

import org.prebid.mobile.VisibilityMonitor;
import org.prebid.mobile.rendering.models.internal.VisibilityTrackerResult;
import org.prebid.mobile.rendering.networking.tracking.ServerConnection;

/* loaded from: classes3.dex */
public final /* synthetic */ class d {
    public final /* synthetic */ VisibilityMonitor.VisibilityTimer a;

    public final void a(VisibilityTrackerResult visibilityTrackerResult) {
        int i = VisibilityMonitor.VisibilityTimer.g;
        VisibilityMonitor.VisibilityTimer visibilityTimer = this.a;
        if (visibilityTrackerResult.c) {
            LogUtil.e(3, "VisibilityTimer", "View is visible. Firing event: " + visibilityTimer.c);
            ServerConnection.a(visibilityTimer.c);
            visibilityTimer.f.a();
        }
    }
}
