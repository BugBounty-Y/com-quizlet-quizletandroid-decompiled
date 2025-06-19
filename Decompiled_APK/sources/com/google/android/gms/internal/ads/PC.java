package com.google.android.gms.internal.ads;

import android.content.Context;
import android.media.AudioFocusRequest;
import android.media.AudioManager;
import android.os.Handler;
import android.os.Looper;
import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class PC {
    public final Bt a;
    public final Handler b;
    public C2436oD c;
    public Wl d;
    public int f;
    public C1711Ie h;
    public float g = 1.0f;
    public int e = 0;

    public PC(final Context context, Looper looper, C2436oD c2436oD) {
        this.a = AbstractC2457os.e(new Bt() { // from class: com.google.android.gms.internal.ads.OC
            @Override // com.google.android.gms.internal.ads.Bt
            public final Object zza() {
                return AbstractC1795We.s(context);
            }
        });
        this.c = c2436oD;
        this.b = new Handler(looper);
    }

    /* JADX WARN: Type inference failed for: r2v2, types: [com.google.android.gms.internal.ads.NC] */
    public final int a(int i, boolean z) {
        if (i == 1 || this.f != 1) {
            d();
            f(0);
            return 1;
        }
        if (!z) {
            int i2 = this.e;
            if (i2 == 1) {
                return -1;
            }
            if (i2 == 3) {
                return 0;
            }
        } else if (this.e != 2) {
            if (this.h == null) {
                Wl wl = Wl.b;
                Wl wl2 = this.d;
                wl2.getClass();
                ?? r2 = new AudioManager.OnAudioFocusChangeListener() { // from class: com.google.android.gms.internal.ads.NC
                    @Override // android.media.AudioManager.OnAudioFocusChangeListener
                    public final void onAudioFocusChange(int i3) {
                        PC pc = this.a;
                        if (i3 == -3 || i3 == -2) {
                            if (i3 != -2) {
                                pc.f(4);
                                return;
                            } else {
                                pc.e(0);
                                pc.f(3);
                                return;
                            }
                        }
                        if (i3 == -1) {
                            pc.e(-1);
                            pc.d();
                            pc.f(1);
                        } else if (i3 != 1) {
                            AbstractC1642h.s(i3, "Unknown focus change type: ", "AudioFocusManager");
                        } else {
                            pc.f(2);
                            pc.e(1);
                        }
                    }
                };
                Handler handler = this.b;
                handler.getClass();
                this.h = new C1711Ie(r2, handler, wl2);
            }
            AudioManager audioManager = (AudioManager) this.a.zza();
            AudioFocusRequest audioFocusRequest = this.h.d;
            audioFocusRequest.getClass();
            if (audioManager.requestAudioFocus(audioFocusRequest) == 1) {
                f(2);
                return 1;
            }
            f(1);
            return -1;
        }
        return 1;
    }

    public final void b() {
        this.c = null;
        d();
        f(0);
    }

    public final void c(Wl wl) {
        if (Objects.equals(this.d, wl)) {
            return;
        }
        this.d = wl;
        this.f = wl == null ? 0 : 1;
    }

    public final void d() {
        int i = this.e;
        if (i == 1 || i == 0 || this.h == null) {
            return;
        }
        AudioManager audioManager = (AudioManager) this.a.zza();
        AudioFocusRequest audioFocusRequest = this.h.d;
        audioFocusRequest.getClass();
        audioManager.abandonAudioFocusRequest(audioFocusRequest);
    }

    public final void e(int i) {
        C2436oD c2436oD = this.c;
        if (c2436oD != null) {
            Bo bo = c2436oD.h;
            bo.getClass();
            C2367mo c2367moE = Bo.e();
            c2367moE.a = bo.a.obtainMessage(33, i, 0);
            c2367moE.a();
        }
    }

    public final void f(int i) {
        if (this.e == i) {
            return;
        }
        this.e = i;
        float f = i == 4 ? 0.2f : 1.0f;
        if (this.g != f) {
            this.g = f;
            C2436oD c2436oD = this.c;
            if (c2436oD != null) {
                c2436oD.h.c(34);
            }
        }
    }
}
