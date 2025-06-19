package com.google.android.gms.internal.ads;

import android.content.Context;
import android.media.AudioDeviceCallback;
import android.media.AudioDeviceInfo;
import java.util.Objects;

/* renamed from: com.google.android.gms.internal.ads.fE, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2048fE extends AudioDeviceCallback {
    public final /* synthetic */ Tm a;

    public /* synthetic */ C2048fE(Tm tm) {
        this.a = tm;
    }

    @Override // android.media.AudioDeviceCallback
    public final void onAudioDevicesAdded(AudioDeviceInfo[] audioDeviceInfoArr) {
        Tm tm = this.a;
        tm.b(C2004eE.b((Context) tm.b, (Wl) tm.i, (C2883yp) tm.h));
    }

    @Override // android.media.AudioDeviceCallback
    public final void onAudioDevicesRemoved(AudioDeviceInfo[] audioDeviceInfoArr) {
        Tm tm = this.a;
        C2883yp c2883yp = (C2883yp) tm.h;
        String str = Yo.a;
        int length = audioDeviceInfoArr.length;
        int i = 0;
        while (true) {
            if (i >= length) {
                break;
            }
            if (Objects.equals(audioDeviceInfoArr[i], c2883yp)) {
                tm.h = null;
                break;
            }
            i++;
        }
        tm.b(C2004eE.b((Context) tm.b, (Wl) tm.i, (C2883yp) tm.h));
    }
}
