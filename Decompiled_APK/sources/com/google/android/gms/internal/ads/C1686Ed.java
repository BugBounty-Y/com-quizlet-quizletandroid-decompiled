package com.google.android.gms.internal.ads;

import android.content.Context;
import android.media.AudioManager;
import com.skydoves.balloon.internals.DefinitionKt;

/* renamed from: com.google.android.gms.internal.ads.Ed, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1686Ed implements AudioManager.OnAudioFocusChangeListener {
    public final AudioManager a;
    public final AbstractC2656td b;
    public boolean c;
    public boolean d;
    public boolean e;
    public float f = 1.0f;

    public C1686Ed(Context context, AbstractC2656td abstractC2656td) {
        this.a = (AudioManager) context.getSystemService("audio");
        this.b = abstractC2656td;
    }

    public final void a() {
        boolean z = this.d;
        AbstractC2656td abstractC2656td = this.b;
        AudioManager audioManager = this.a;
        if (!z || this.e || this.f <= DefinitionKt.NO_Float_VALUE) {
            if (this.c) {
                if (audioManager != null) {
                    this.c = audioManager.abandonAudioFocus(this) == 0;
                }
                abstractC2656td.m();
                return;
            }
            return;
        }
        if (this.c) {
            return;
        }
        if (audioManager != null) {
            this.c = audioManager.requestAudioFocus(this, 3, 2) == 1;
        }
        abstractC2656td.m();
    }

    @Override // android.media.AudioManager.OnAudioFocusChangeListener
    public final void onAudioFocusChange(int i) {
        this.c = i > 0;
        this.b.m();
    }
}
