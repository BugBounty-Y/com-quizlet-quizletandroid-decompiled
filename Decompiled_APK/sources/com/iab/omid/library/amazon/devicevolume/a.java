package com.iab.omid.library.amazon.devicevolume;

import android.content.Context;
import android.database.ContentObserver;
import android.media.AudioManager;
import android.os.Handler;
import com.airbnb.lottie.animation.keyframe.c;
import com.google.android.material.shape.e;
import com.iab.omid.library.amazon.adsession.k;
import com.iab.omid.library.amazon.internal.h;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Collections;
import java.util.Iterator;

/* loaded from: classes2.dex */
public final class a extends ContentObserver {
    public final Context a;
    public final AudioManager b;
    public final e c;
    public final c d;
    public float e;

    public a(Handler handler, Context context, e eVar, c cVar) {
        super(handler);
        this.a = context;
        this.b = (AudioManager) context.getSystemService("audio");
        this.c = eVar;
        this.d = cVar;
    }

    public final float a() {
        AudioManager audioManager = this.b;
        int streamVolume = audioManager.getStreamVolume(3);
        int streamMaxVolume = audioManager.getStreamMaxVolume(3);
        this.c.getClass();
        if (streamMaxVolume <= 0 || streamVolume <= 0) {
            return DefinitionKt.NO_Float_VALUE;
        }
        float f = streamVolume / streamMaxVolume;
        if (f > 1.0f) {
            return 1.0f;
        }
        return f;
    }

    public final void b() {
        float f = this.e;
        c cVar = this.d;
        cVar.a = f;
        if (((com.iab.omid.library.amazon.internal.c) cVar.d) == null) {
            cVar.d = com.iab.omid.library.amazon.internal.c.c;
        }
        Iterator it2 = Collections.unmodifiableCollection(((com.iab.omid.library.amazon.internal.c) cVar.d).b).iterator();
        while (it2.hasNext()) {
            com.iab.omid.library.amazon.publisher.a aVar = ((k) it2.next()).e;
            h.a.a(aVar.e(), "setDeviceVolume", Float.valueOf(f), aVar.a);
        }
    }

    @Override // android.database.ContentObserver
    public final void onChange(boolean z) {
        super.onChange(z);
        float fA = a();
        if (fA != this.e) {
            this.e = fA;
            b();
        }
    }
}
