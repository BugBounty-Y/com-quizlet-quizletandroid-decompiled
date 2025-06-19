package com.pubmatic.sdk.openwrap.banner;

import android.view.View;
import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public abstract class a extends com.pubmatic.sdk.openwrap.core.e {
    public com.pubmatic.sdk.openwrap.core.d getAdInteractionListener() {
        return null;
    }

    public View getAdServerView() {
        return null;
    }

    public com.pubmatic.sdk.common.f getAdSize() {
        return null;
    }

    public com.pubmatic.sdk.common.ui.a getRenderer(String str) {
        return null;
    }

    public com.pubmatic.sdk.common.f[] requestedAdSizes() {
        return null;
    }

    public abstract void setEventListener(@NonNull b bVar);
}
