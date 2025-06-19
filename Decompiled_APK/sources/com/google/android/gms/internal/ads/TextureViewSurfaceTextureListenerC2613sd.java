package com.google.android.gms.internal.ads;

import android.content.Context;
import android.graphics.SurfaceTexture;
import android.media.MediaPlayer;
import android.net.Uri;
import android.view.Surface;
import android.view.TextureView;
import com.comscore.streaming.ContentDeliveryAdvertisementCapability;
import com.comscore.streaming.ContentDeliveryComposition;
import com.comscore.streaming.ContentDistributionModel;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.IOException;
import java.util.HashMap;

/* renamed from: com.google.android.gms.internal.ads.sd, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class TextureViewSurfaceTextureListenerC2613sd extends AbstractC2656td implements TextureView.SurfaceTextureListener, MediaPlayer.OnBufferingUpdateListener, MediaPlayer.OnCompletionListener, MediaPlayer.OnErrorListener, MediaPlayer.OnInfoListener, MediaPlayer.OnPreparedListener, MediaPlayer.OnVideoSizeChangedListener {
    public static final HashMap t;
    public final C2743ve c;
    public final C1674Cd d;
    public final boolean e;
    public final Hk f;
    public int g;
    public int h;
    public MediaPlayer i;
    public Uri j;
    public int k;
    public int l;
    public int m;
    public C1662Ad n;
    public final boolean o;
    public int p;
    public C2785wd q;
    public boolean r;
    public Integer s;

    static {
        HashMap map = new HashMap();
        t = map;
        map.put(-1004, "MEDIA_ERROR_IO");
        map.put(-1007, "MEDIA_ERROR_MALFORMED");
        map.put(-1010, "MEDIA_ERROR_UNSUPPORTED");
        map.put(-110, "MEDIA_ERROR_TIMED_OUT");
        map.put(3, "MEDIA_INFO_VIDEO_RENDERING_START");
        map.put(100, "MEDIA_ERROR_SERVER_DIED");
        map.put(1, "MEDIA_ERROR_UNKNOWN");
        map.put(1, "MEDIA_INFO_UNKNOWN");
        map.put(700, "MEDIA_INFO_VIDEO_TRACK_LAGGING");
        map.put(Integer.valueOf(ContentDeliveryComposition.CLEAN), "MEDIA_INFO_BUFFERING_START");
        map.put(Integer.valueOf(ContentDeliveryComposition.EMBED), "MEDIA_INFO_BUFFERING_END");
        map.put(800, "MEDIA_INFO_BAD_INTERLEAVING");
        map.put(Integer.valueOf(ContentDeliveryAdvertisementCapability.NONE), "MEDIA_INFO_NOT_SEEKABLE");
        map.put(Integer.valueOf(ContentDeliveryAdvertisementCapability.DYNAMIC_LOAD), "MEDIA_INFO_METADATA_UPDATE");
        map.put(Integer.valueOf(ContentDistributionModel.TV_AND_ONLINE), "MEDIA_INFO_UNSUPPORTED_SUBTITLE");
        map.put(Integer.valueOf(ContentDistributionModel.EXCLUSIVELY_ONLINE), "MEDIA_INFO_SUBTITLE_TIMED_OUT");
    }

    public TextureViewSurfaceTextureListenerC2613sd(Context context, C2743ve c2743ve, boolean z, boolean z2, C1674Cd c1674Cd, Hk hk) {
        super(context);
        this.g = 0;
        this.h = 0;
        this.r = false;
        this.s = null;
        this.c = c2743ve;
        this.d = c1674Cd;
        this.o = z;
        this.e = z2;
        c1674Cd.a(this);
        this.f = hk;
    }

    public final void E() throws IllegalStateException, InterruptedException, IOException, SecurityException, IllegalArgumentException {
        SurfaceTexture surfaceTexture;
        Hk hk;
        com.google.android.gms.ads.internal.util.A.l("AdMediaPlayerView init MediaPlayer");
        SurfaceTexture surfaceTexture2 = getSurfaceTexture();
        if (this.j == null || surfaceTexture2 == null) {
            return;
        }
        F(false);
        try {
            com.quizlet.shared.usecase.studiableMetadata.a aVar = com.google.android.gms.ads.internal.j.C.u;
            MediaPlayer mediaPlayer = new MediaPlayer();
            this.i = mediaPlayer;
            mediaPlayer.setOnBufferingUpdateListener(this);
            this.i.setOnCompletionListener(this);
            this.i.setOnErrorListener(this);
            this.i.setOnInfoListener(this);
            this.i.setOnPreparedListener(this);
            this.i.setOnVideoSizeChangedListener(this);
            this.m = 0;
            if (this.o) {
                if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.hd)).booleanValue() && (hk = this.f) != null) {
                    Fi fiA = hk.a();
                    fiA.o("action", "svp_ampv");
                    fiA.x();
                }
                C1662Ad c1662Ad = new C1662Ad(getContext());
                this.n = c1662Ad;
                int width = getWidth();
                int height = getHeight();
                c1662Ad.m = width;
                c1662Ad.l = height;
                c1662Ad.o = surfaceTexture2;
                C1662Ad c1662Ad2 = this.n;
                c1662Ad2.start();
                if (c1662Ad2.o == null) {
                    surfaceTexture = null;
                } else {
                    try {
                        c1662Ad2.t.await();
                    } catch (InterruptedException unused) {
                    }
                    surfaceTexture = c1662Ad2.n;
                }
                if (surfaceTexture != null) {
                    surfaceTexture2 = surfaceTexture;
                } else {
                    this.n.b();
                    this.n = null;
                }
            }
            this.i.setDataSource(getContext(), this.j);
            this.i.setSurface(new Surface(surfaceTexture2));
            this.i.setAudioStreamType(3);
            this.i.setScreenOnWhilePlaying(true);
            this.i.prepareAsync();
            G(1);
        } catch (IOException e) {
            e = e;
            com.google.android.gms.ads.internal.util.client.i.i("Failed to initialize MediaPlayer at ".concat(String.valueOf(this.j)), e);
            onError(this.i, 1, 0);
        } catch (IllegalArgumentException e2) {
            e = e2;
            com.google.android.gms.ads.internal.util.client.i.i("Failed to initialize MediaPlayer at ".concat(String.valueOf(this.j)), e);
            onError(this.i, 1, 0);
        } catch (IllegalStateException e3) {
            e = e3;
            com.google.android.gms.ads.internal.util.client.i.i("Failed to initialize MediaPlayer at ".concat(String.valueOf(this.j)), e);
            onError(this.i, 1, 0);
        }
    }

    public final void F(boolean z) {
        com.google.android.gms.ads.internal.util.A.l("AdMediaPlayerView release");
        C1662Ad c1662Ad = this.n;
        if (c1662Ad != null) {
            c1662Ad.b();
            this.n = null;
        }
        MediaPlayer mediaPlayer = this.i;
        if (mediaPlayer != null) {
            mediaPlayer.reset();
            this.i.release();
            this.i = null;
            G(0);
            if (z) {
                this.h = 0;
            }
        }
    }

    public final void G(int i) {
        C1686Ed c1686Ed = this.b;
        C1674Cd c1674Cd = this.d;
        if (i == 3) {
            c1674Cd.b();
            c1686Ed.d = true;
            c1686Ed.a();
        } else if (this.g == 3) {
            c1674Cd.m = false;
            c1686Ed.d = false;
            c1686Ed.a();
        }
        this.g = i;
    }

    public final boolean H() {
        int i;
        return (this.i == null || (i = this.g) == -1 || i == 0 || i == 1) ? false : true;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final int j() {
        if (H()) {
            return this.i.getCurrentPosition();
        }
        return 0;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final int k() {
        if (H()) {
            return this.i.getMetrics().getInt("android.media.mediaplayer.dropped");
        }
        return -1;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final int l() {
        if (H()) {
            return this.i.getDuration();
        }
        return -1;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1680Dd
    public final void m() {
        C1686Ed c1686Ed = this.b;
        boolean z = c1686Ed.e;
        float f = DefinitionKt.NO_Float_VALUE;
        float f2 = z ? 0.0f : c1686Ed.f;
        if (c1686Ed.c) {
            f = f2;
        }
        MediaPlayer mediaPlayer = this.i;
        if (mediaPlayer == null) {
            com.google.android.gms.ads.internal.util.client.i.h("AdMediaPlayerView setMediaPlayerVolume() called before onPrepared().");
        } else {
            try {
                mediaPlayer.setVolume(f, f);
            } catch (IllegalStateException unused) {
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final int n() {
        MediaPlayer mediaPlayer = this.i;
        if (mediaPlayer != null) {
            return mediaPlayer.getVideoHeight();
        }
        return 0;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final int o() {
        MediaPlayer mediaPlayer = this.i;
        if (mediaPlayer != null) {
            return mediaPlayer.getVideoWidth();
        }
        return 0;
    }

    @Override // android.view.TextureView, android.view.View
    public final void onAttachedToWindow() {
        super.onAttachedToWindow();
        setSurfaceTextureListener(this);
    }

    @Override // android.media.MediaPlayer.OnBufferingUpdateListener
    public final void onBufferingUpdate(MediaPlayer mediaPlayer, int i) {
        this.m = i;
    }

    @Override // android.media.MediaPlayer.OnCompletionListener
    public final void onCompletion(MediaPlayer mediaPlayer) {
        com.google.android.gms.ads.internal.util.A.l("AdMediaPlayerView completion");
        G(5);
        this.h = 5;
        com.google.android.gms.ads.internal.util.F.l.post(new RunnableC2528qd(this, 0));
    }

    @Override // android.media.MediaPlayer.OnErrorListener
    public final boolean onError(MediaPlayer mediaPlayer, int i, int i2) {
        HashMap map = t;
        String str = (String) map.get(Integer.valueOf(i));
        String str2 = (String) map.get(Integer.valueOf(i2));
        com.google.android.gms.ads.internal.util.client.i.h("AdMediaPlayerView MediaPlayer error: " + str + ":" + str2);
        G(-1);
        this.h = -1;
        com.google.android.gms.ads.internal.util.F.l.post(new C(4, this, str, str2, false));
        return true;
    }

    @Override // android.media.MediaPlayer.OnInfoListener
    public final boolean onInfo(MediaPlayer mediaPlayer, int i, int i2) {
        HashMap map = t;
        com.google.android.gms.ads.internal.util.A.l("AdMediaPlayerView MediaPlayer info: " + ((String) map.get(Integer.valueOf(i))) + ":" + ((String) map.get(Integer.valueOf(i2))));
        return true;
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x0047  */
    /* JADX WARN: Removed duplicated region for block: B:26:0x0054  */
    @Override // android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void onMeasure(int r6, int r7) {
        /*
            r5 = this;
            int r0 = r5.k
            int r0 = android.view.View.getDefaultSize(r0, r6)
            int r1 = r5.l
            int r1 = android.view.View.getDefaultSize(r1, r7)
            int r2 = r5.k
            if (r2 <= 0) goto L7a
            int r2 = r5.l
            if (r2 <= 0) goto L7a
            com.google.android.gms.internal.ads.Ad r2 = r5.n
            if (r2 != 0) goto L7a
            int r0 = android.view.View.MeasureSpec.getMode(r6)
            int r6 = android.view.View.MeasureSpec.getSize(r6)
            int r1 = android.view.View.MeasureSpec.getMode(r7)
            int r7 = android.view.View.MeasureSpec.getSize(r7)
            r2 = 1073741824(0x40000000, float:2.0)
            if (r0 != r2) goto L43
            if (r1 != r2) goto L42
            int r0 = r5.k
            int r1 = r0 * r7
            int r2 = r5.l
            int r3 = r6 * r2
            if (r1 >= r3) goto L3c
            int r0 = r1 / r2
        L3a:
            r1 = r7
            goto L7a
        L3c:
            if (r1 <= r3) goto L60
            int r1 = r3 / r0
        L40:
            r0 = r6
            goto L7a
        L42:
            r0 = r2
        L43:
            r3 = -2147483648(0xffffffff80000000, float:-0.0)
            if (r0 != r2) goto L54
            int r0 = r5.l
            int r0 = r0 * r6
            int r2 = r5.k
            int r0 = r0 / r2
            if (r1 != r3) goto L52
            if (r0 <= r7) goto L52
            goto L60
        L52:
            r1 = r0
            goto L40
        L54:
            if (r1 != r2) goto L64
            int r1 = r5.k
            int r1 = r1 * r7
            int r2 = r5.l
            int r1 = r1 / r2
            if (r0 != r3) goto L62
            if (r1 <= r6) goto L62
        L60:
            r0 = r6
            goto L3a
        L62:
            r0 = r1
            goto L3a
        L64:
            int r2 = r5.k
            int r4 = r5.l
            if (r1 != r3) goto L70
            if (r4 <= r7) goto L70
            int r1 = r7 * r2
            int r1 = r1 / r4
            goto L72
        L70:
            r1 = r2
            r7 = r4
        L72:
            if (r0 != r3) goto L62
            if (r1 <= r6) goto L62
            int r4 = r4 * r6
            int r1 = r4 / r2
            goto L40
        L7a:
            r5.setMeasuredDimension(r0, r1)
            com.google.android.gms.internal.ads.Ad r6 = r5.n
            if (r6 == 0) goto L84
            r6.a(r0, r1)
        L84:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.TextureViewSurfaceTextureListenerC2613sd.onMeasure(int, int):void");
    }

    @Override // android.media.MediaPlayer.OnPreparedListener
    public final void onPrepared(MediaPlayer mediaPlayer) throws IllegalStateException {
        com.google.android.gms.ads.internal.util.A.l("AdMediaPlayerView prepared");
        G(2);
        C1674Cd c1674Cd = this.d;
        if (c1674Cd.i && !c1674Cd.j) {
            AbstractC2096gb.h(c1674Cd.e, c1674Cd.d, "vfr2");
            c1674Cd.j = true;
        }
        com.google.android.gms.ads.internal.util.F.l.post(new Qv(this, false, mediaPlayer, 14));
        this.k = mediaPlayer.getVideoWidth();
        this.l = mediaPlayer.getVideoHeight();
        int i = this.p;
        if (i != 0) {
            v(i);
        }
        if (this.e && H() && this.i.getCurrentPosition() > 0 && this.h != 3) {
            com.google.android.gms.ads.internal.util.A.l("AdMediaPlayerView nudging MediaPlayer");
            MediaPlayer mediaPlayer2 = this.i;
            if (mediaPlayer2 != null) {
                try {
                    mediaPlayer2.setVolume(DefinitionKt.NO_Float_VALUE, DefinitionKt.NO_Float_VALUE);
                } catch (IllegalStateException unused) {
                }
            } else {
                com.google.android.gms.ads.internal.util.client.i.h("AdMediaPlayerView setMediaPlayerVolume() called before onPrepared().");
            }
            this.i.start();
            int currentPosition = this.i.getCurrentPosition();
            com.google.android.gms.ads.internal.j.C.k.getClass();
            long jCurrentTimeMillis = System.currentTimeMillis();
            while (H() && this.i.getCurrentPosition() == currentPosition) {
                com.google.android.gms.ads.internal.j.C.k.getClass();
                if (System.currentTimeMillis() - jCurrentTimeMillis > 250) {
                    break;
                }
            }
            this.i.pause();
            m();
        }
        com.google.android.gms.ads.internal.util.client.i.g("AdMediaPlayerView stream dimensions: " + this.k + " x " + this.l);
        if (this.h == 3) {
            u();
        }
        m();
    }

    @Override // android.view.TextureView.SurfaceTextureListener
    public final void onSurfaceTextureAvailable(SurfaceTexture surfaceTexture, int i, int i2) throws IllegalStateException, InterruptedException, IOException, SecurityException, IllegalArgumentException {
        com.google.android.gms.ads.internal.util.A.l("AdMediaPlayerView surface created");
        E();
        com.google.android.gms.ads.internal.util.F.l.post(new RunnableC2528qd(this, 1));
    }

    @Override // android.view.TextureView.SurfaceTextureListener
    public final boolean onSurfaceTextureDestroyed(SurfaceTexture surfaceTexture) {
        com.google.android.gms.ads.internal.util.A.l("AdMediaPlayerView surface destroyed");
        MediaPlayer mediaPlayer = this.i;
        if (mediaPlayer != null && this.p == 0) {
            this.p = mediaPlayer.getCurrentPosition();
        }
        C1662Ad c1662Ad = this.n;
        if (c1662Ad != null) {
            c1662Ad.b();
        }
        com.google.android.gms.ads.internal.util.F.l.post(new RunnableC2528qd(this, 2));
        F(true);
        return true;
    }

    @Override // android.view.TextureView.SurfaceTextureListener
    public final void onSurfaceTextureSizeChanged(SurfaceTexture surfaceTexture, int i, int i2) throws IllegalStateException {
        com.google.android.gms.ads.internal.util.A.l("AdMediaPlayerView surface changed");
        int i3 = this.h;
        boolean z = false;
        if (this.k == i && this.l == i2) {
            z = true;
        }
        if (this.i != null && i3 == 3 && z) {
            int i4 = this.p;
            if (i4 != 0) {
                v(i4);
            }
            u();
        }
        C1662Ad c1662Ad = this.n;
        if (c1662Ad != null) {
            c1662Ad.a(i, i2);
        }
        com.google.android.gms.ads.internal.util.F.l.post(new RunnableC2570rd(this, i, i2, 0));
    }

    @Override // android.view.TextureView.SurfaceTextureListener
    public final void onSurfaceTextureUpdated(SurfaceTexture surfaceTexture) {
        this.d.d(this);
        this.a.b(surfaceTexture, this.q);
    }

    @Override // android.media.MediaPlayer.OnVideoSizeChangedListener
    public final void onVideoSizeChanged(MediaPlayer mediaPlayer, int i, int i2) {
        com.google.android.gms.ads.internal.util.A.l("AdMediaPlayerView size changed: " + i + " x " + i2);
        this.k = mediaPlayer.getVideoWidth();
        int videoHeight = mediaPlayer.getVideoHeight();
        this.l = videoHeight;
        if (this.k == 0 || videoHeight == 0) {
            return;
        }
        requestLayout();
    }

    @Override // android.view.View
    public final void onWindowVisibilityChanged(int i) {
        com.google.android.gms.ads.internal.util.A.l("AdMediaPlayerView window visibility changed to " + i);
        com.google.android.gms.ads.internal.util.F.l.post(new androidx.core.provider.a(this, i, 6));
        super.onWindowVisibilityChanged(i);
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final long p() {
        return 0L;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final long q() {
        if (this.s != null) {
            return (r() * this.m) / 100;
        }
        return -1L;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final long r() {
        if (this.s != null) {
            return l() * this.s.intValue();
        }
        return -1L;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final String s() {
        return "MediaPlayer".concat(true != this.o ? "" : " spherical");
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final void t() throws IllegalStateException {
        com.google.android.gms.ads.internal.util.A.l("AdMediaPlayerView pause");
        if (H() && this.i.isPlaying()) {
            this.i.pause();
            G(4);
            com.google.android.gms.ads.internal.util.F.l.post(new RunnableC2528qd(this, 4));
        }
        this.h = 4;
    }

    @Override // android.view.View
    public final String toString() {
        return android.support.v4.media.session.a.l(TextureViewSurfaceTextureListenerC2613sd.class.getName(), "@", Integer.toHexString(hashCode()));
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final void u() throws IllegalStateException {
        com.google.android.gms.ads.internal.util.A.l("AdMediaPlayerView play");
        if (H()) {
            this.i.start();
            G(3);
            this.a.c = true;
            com.google.android.gms.ads.internal.util.F.l.post(new RunnableC2528qd(this, 3));
        }
        this.h = 3;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final void v(int i) throws IllegalStateException {
        com.google.android.gms.ads.internal.util.A.l("AdMediaPlayerView seek " + i);
        if (!H()) {
            this.p = i;
        } else {
            this.i.seekTo(i);
            this.p = 0;
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final void w(C2785wd c2785wd) {
        this.q = c2785wd;
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final void x(String str) throws IllegalStateException, InterruptedException, IOException, SecurityException, IllegalArgumentException {
        Uri uri = Uri.parse(str);
        zzbbf zzbbfVarA = zzbbf.a(uri);
        if (zzbbfVarA == null || zzbbfVarA.a != null) {
            if (zzbbfVarA != null) {
                uri = Uri.parse(zzbbfVarA.a);
            }
            this.j = uri;
            this.p = 0;
            E();
            requestLayout();
            invalidate();
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final void y() throws IllegalStateException {
        com.google.android.gms.ads.internal.util.A.l("AdMediaPlayerView stop");
        MediaPlayer mediaPlayer = this.i;
        if (mediaPlayer != null) {
            mediaPlayer.stop();
            this.i.release();
            this.i = null;
            G(0);
            this.h = 0;
        }
        this.d.c();
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2656td
    public final void z(float f, float f2) {
        C1662Ad c1662Ad = this.n;
        if (c1662Ad != null) {
            c1662Ad.c(f, f2);
        }
    }
}
