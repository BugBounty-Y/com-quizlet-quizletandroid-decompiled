package com.braze.events;

import com.braze.models.Banner;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class BannersUpdatedEvent {
    public static final Companion Companion = new Companion(null);
    private final List<Banner> banners;

    @Metadata
    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private Companion() {
        }
    }

    public BannersUpdatedEvent(List<Banner> banners) {
        Intrinsics.checkNotNullParameter(banners, "banners");
        this.banners = banners;
    }

    public String toString() {
        return "BannersUpdatedEvent{banner count=" + this.banners.size() + '}';
    }
}
