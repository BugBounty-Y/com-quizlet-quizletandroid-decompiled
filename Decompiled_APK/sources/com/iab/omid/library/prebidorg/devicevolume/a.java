package com.iab.omid.library.prebidorg.devicevolume;

import android.content.Context;
import android.database.ContentObserver;
import android.media.AudioManager;
import android.os.Handler;
import com.google.mlkit.common.sdkinternal.b;
import com.quizlet.data.repository.searchexplanations.c;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.Collections;
import java.util.Iterator;

/* loaded from: classes2.dex */
public final class a extends ContentObserver {
    public final AudioManager a;
    public final b b;
    public final c c;
    public float d;

    public a(Handler handler, Context context, b bVar, c cVar) {
        super(handler);
        this.a = (AudioManager) context.getSystemService("audio");
        this.b = bVar;
        this.c = cVar;
    }

    @Override // android.database.ContentObserver
    public final void onChange(boolean z) {
        float f;
        super.onChange(z);
        AudioManager audioManager = this.a;
        int streamVolume = audioManager.getStreamVolume(3);
        int streamMaxVolume = audioManager.getStreamMaxVolume(3);
        this.b.getClass();
        if (streamMaxVolume <= 0 || streamVolume <= 0) {
            f = DefinitionKt.NO_Float_VALUE;
        } else {
            f = streamVolume / streamMaxVolume;
            if (f > 1.0f) {
                f = 1.0f;
            }
        }
        if (f != this.d) {
            this.d = f;
            c cVar = this.c;
            if (((com.iab.omid.library.prebidorg.internal.c) cVar.c) == null) {
                cVar.c = com.iab.omid.library.prebidorg.internal.c.c;
            }
            Iterator it2 = Collections.unmodifiableCollection(((com.iab.omid.library.prebidorg.internal.c) cVar.c).b).iterator();
            if (it2.hasNext()) {
                throw android.support.v4.media.session.a.d(it2);
            }
        }
    }
}
