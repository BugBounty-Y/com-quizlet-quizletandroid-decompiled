package com.pubmatic.sdk.common.network;

import androidx.annotation.NonNull;
import androidx.compose.animation.d0;
import java.util.Map;

/* loaded from: classes2.dex */
public class l {

    @NonNull
    private Map<String, String> a;
    private long b;

    public l(@NonNull Map<String, String> map, long j) {
        this.a = map;
        this.b = j;
    }

    @NonNull
    public Map<String, String> getHeaders() {
        return this.a;
    }

    public long getNetworkTimeMs() {
        return this.b;
    }

    @NonNull
    public String toString() {
        return d0.q(new StringBuilder("POBNetworkResult{ networkTimeMs="), this.b, '}');
    }
}
