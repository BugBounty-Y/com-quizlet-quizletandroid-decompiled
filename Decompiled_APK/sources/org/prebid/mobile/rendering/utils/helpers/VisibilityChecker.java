package org.prebid.mobile.rendering.utils.helpers;

import android.graphics.Rect;
import org.prebid.mobile.rendering.models.internal.VisibilityTrackerOption;
import org.prebid.mobile.rendering.utils.exposure.ViewExposureChecker;

/* loaded from: classes3.dex */
public class VisibilityChecker {
    public final VisibilityTrackerOption a;
    public final ViewExposureChecker b;
    public final Rect c = new Rect();

    public VisibilityChecker(VisibilityTrackerOption visibilityTrackerOption, ViewExposureChecker viewExposureChecker) {
        this.a = visibilityTrackerOption;
        this.b = viewExposureChecker;
    }
}
