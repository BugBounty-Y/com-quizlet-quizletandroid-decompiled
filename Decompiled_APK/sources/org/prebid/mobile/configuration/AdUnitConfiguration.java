package org.prebid.mobile.configuration;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Random;
import java.util.UUID;
import org.prebid.mobile.api.data.AdFormat;
import org.prebid.mobile.api.data.Position;
import org.prebid.mobile.rendering.interstitial.rewarded.RewardManager;
import org.prebid.mobile.rendering.models.AdPosition;

/* loaded from: classes3.dex */
public class AdUnitConfiguration {
    public boolean a = false;
    public boolean b = false;
    public int c = 0;
    public int d = 10;
    public double e;
    public double f;
    public int g;
    public String h;
    public Position i;
    public Position j;
    public final AdPosition k;
    public NativeAdUnitConfiguration l;
    public final EnumSet m;
    public final HashSet n;

    public AdUnitConfiguration() {
        new Random().nextInt(SubsamplingScaleImageView.TILE_SIZE_AUTO);
        this.e = 0.0d;
        this.f = 0.0d;
        this.g = 3600;
        UUID uuidRandomUUID = UUID.randomUUID();
        new UUID(uuidRandomUUID.getMostSignificantBits(), System.currentTimeMillis()).toString();
        Position position = Position.c;
        this.i = position;
        this.j = position;
        this.k = AdPosition.UNDEFINED;
        new RewardManager();
        this.m = EnumSet.noneOf(AdFormat.class);
        this.n = new HashSet();
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && getClass() == obj.getClass()) {
            String str = this.h;
            String str2 = ((AdUnitConfiguration) obj).h;
            if (str != null) {
                return str.equals(str2);
            }
            if (str2 == null) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        String str = this.h;
        if (str != null) {
            return str.hashCode();
        }
        return 0;
    }
}
