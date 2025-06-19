package com.google.android.gms.internal.ads;

import android.media.AudioTrack;
import android.media.AudioTrack$StreamEventCallback;

/* renamed from: com.google.android.gms.internal.ads.rE, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2565rE extends AudioTrack$StreamEventCallback {
    public final /* synthetic */ Iw a;

    public C2565rE(Iw iw) {
        this.a = iw;
    }

    public final void onDataRequest(AudioTrack audioTrack, int i) {
        audioTrack.equals(((C2608sE) this.a.b).p);
    }

    public final void onPresentationEnded(AudioTrack audioTrack) {
        C2608sE c2608sE = (C2608sE) this.a.b;
        if (audioTrack.equals(c2608sE.p)) {
            c2608sE.M = true;
        }
    }

    public final void onTearDown(AudioTrack audioTrack) {
        audioTrack.equals(((C2608sE) this.a.b).p);
    }
}
