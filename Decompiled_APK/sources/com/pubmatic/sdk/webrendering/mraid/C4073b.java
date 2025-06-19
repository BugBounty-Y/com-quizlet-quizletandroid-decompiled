package com.pubmatic.sdk.webrendering.mraid;

import android.content.Context;
import android.database.ContentObserver;
import android.media.AudioManager;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import androidx.annotation.NonNull;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/* renamed from: com.pubmatic.sdk.webrendering.mraid.b, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public class C4073b {
    private static volatile C4073b a;

    @NonNull
    private final Set<InterfaceC4072a> b = new HashSet();
    private a c;

    /* renamed from: com.pubmatic.sdk.webrendering.mraid.b$a */
    public class a extends ContentObserver {
        private final AudioManager a;
        private int b;

        public a(@NonNull Handler handler, @NonNull AudioManager audioManager) {
            super(handler);
            this.a = audioManager;
            this.b = audioManager.getStreamVolume(3);
        }

        @Override // android.database.ContentObserver
        public void onChange(boolean z, Uri uri) {
            AudioManager audioManager = this.a;
            if (audioManager != null) {
                int streamMaxVolume = audioManager.getStreamMaxVolume(3);
                int streamVolume = this.a.getStreamVolume(3);
                if (streamVolume != this.b) {
                    this.b = streamVolume;
                    C4073b.this.a(streamVolume, streamMaxVolume);
                }
            }
        }
    }

    private C4073b() {
    }

    private void b(@NonNull Context context) {
        if (this.c != null) {
            context.getContentResolver().unregisterContentObserver(this.c);
            this.c = null;
        }
    }

    private void c(Context context) {
        b(context);
        a = null;
    }

    public static Double getAudioVolumePercentage(@NonNull Context context) {
        if (((AudioManager) context.getSystemService("audio")) == null) {
            return null;
        }
        return Double.valueOf((r4.getStreamVolume(3) * 100.0d) / r4.getStreamMaxVolume(3));
    }

    public void registerListener(@NonNull Context context, @NonNull InterfaceC4072a interfaceC4072a) {
        if (this.b.contains(interfaceC4072a)) {
            return;
        }
        if (this.c == null) {
            a(context);
        }
        this.b.add(interfaceC4072a);
    }

    public void unregisterListener(@NonNull Context context, InterfaceC4072a interfaceC4072a) {
        this.b.remove(interfaceC4072a);
        if (this.b.isEmpty()) {
            c(context);
        }
    }

    public static C4073b a() {
        if (a == null) {
            synchronized (C4073b.class) {
                try {
                    if (a == null) {
                        a = new C4073b();
                    }
                } finally {
                }
            }
        }
        return a;
    }

    private void a(@NonNull Context context) {
        if (this.c == null) {
            Handler handler = new Handler(Looper.getMainLooper());
            AudioManager audioManager = (AudioManager) context.getSystemService("audio");
            if (audioManager != null) {
                this.c = new a(handler, audioManager);
                context.getContentResolver().registerContentObserver(Settings.System.CONTENT_URI, true, this.c);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void a(int i, int i2) {
        Double dValueOf = Double.valueOf((i * 100.0d) / i2);
        Iterator<InterfaceC4072a> it2 = this.b.iterator();
        while (it2.hasNext()) {
            it2.next().a(dValueOf);
        }
    }
}
