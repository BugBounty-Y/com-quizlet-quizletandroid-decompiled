package com.google.android.gms.internal.ads;

import android.media.AudioAttributes;
import android.media.AudioFocusRequest;
import android.os.Handler;
import java.util.Objects;

/* renamed from: com.google.android.gms.internal.ads.Ie, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1711Ie {
    public final NC a;
    public final Handler b;
    public final Wl c;
    public final AudioFocusRequest d;

    public C1711Ie(NC nc, Handler handler, Wl wl) {
        this.b = handler;
        this.c = wl;
        this.a = nc;
        this.d = new AudioFocusRequest.Builder(1).setAudioAttributes((AudioAttributes) wl.a().b).setWillPauseWhenDucked(false).setOnAudioFocusChangeListener(nc, handler).build();
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C1711Ie)) {
            return false;
        }
        C1711Ie c1711Ie = (C1711Ie) obj;
        c1711Ie.getClass();
        return equals(c1711Ie.a) && Objects.equals(this.b, c1711Ie.b) && Objects.equals(this.c, c1711Ie.c);
    }

    public final int hashCode() {
        return Objects.hash(1, this.a, this.b, this.c, Boolean.FALSE);
    }
}
