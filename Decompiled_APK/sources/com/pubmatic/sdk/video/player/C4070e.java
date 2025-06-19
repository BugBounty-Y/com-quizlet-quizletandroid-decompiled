package com.pubmatic.sdk.video.player;

import android.media.MediaPlayer;
import android.os.Handler;
import android.os.HandlerThread;
import android.view.Surface;
import androidx.annotation.NonNull;
import androidx.compose.animation.d0;
import com.pubmatic.sdk.common.log.POBLog;
import java.io.IOException;

/* renamed from: com.pubmatic.sdk.video.player.e, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public class C4070e implements com.pubmatic.sdk.video.player.h, MediaPlayer.OnPreparedListener, MediaPlayer.OnBufferingUpdateListener, MediaPlayer.OnErrorListener, MediaPlayer.OnCompletionListener, MediaPlayer.OnInfoListener, MediaPlayer.OnVideoSizeChangedListener {
    private com.pubmatic.sdk.video.player.g a;
    private MediaPlayer b;
    private Handler c;

    @NonNull
    private final HandlerThread d;

    @NonNull
    private final Handler e;
    private com.pubmatic.sdk.common.utility.l f;
    private int g;
    private com.pubmatic.sdk.common.utility.l h;
    private int i;
    private com.pubmatic.sdk.common.utility.l j;
    private int k;
    private int l;
    private int m;
    private int n;

    /* renamed from: com.pubmatic.sdk.video.player.e$a */
    public class a implements Runnable {
        public a() {
        }

        @Override // java.lang.Runnable
        public void run() throws IllegalStateException {
            if (C4070e.this.b != null) {
                C4070e.this.b.stop();
                C4070e.this.h();
                C4070e.this.e.post(new x(this));
            }
        }
    }

    /* renamed from: com.pubmatic.sdk.video.player.e$b */
    public class b implements Runnable {
        final /* synthetic */ int a;
        final /* synthetic */ int b;

        public b(int i, int i2) {
            this.a = i;
            this.b = i2;
        }

        @Override // java.lang.Runnable
        public void run() {
            if (C4070e.this.b != null) {
                C4070e.this.b.setVolume(this.a, this.b);
            }
        }
    }

    /* renamed from: com.pubmatic.sdk.video.player.e$c */
    public class c implements Runnable {
        final /* synthetic */ Surface a;

        public c(Surface surface) {
            this.a = surface;
        }

        @Override // java.lang.Runnable
        public void run() {
            C4070e.this.e();
            if (C4070e.this.b == null || !this.a.isValid()) {
                return;
            }
            try {
                C4070e.this.b.setSurface(this.a);
            } catch (IllegalArgumentException e) {
                POBLog.error("POBMediaPlayer", "Unable to set surface to media player. Reason - " + e.getMessage(), new Object[0]);
            }
        }
    }

    /* renamed from: com.pubmatic.sdk.video.player.e$d */
    public class d implements Runnable {
        public d() {
        }

        @Override // java.lang.Runnable
        public void run() {
            C4070e.this.h();
            if (C4070e.this.b != null) {
                C4070e.this.b.setSurface(null);
            }
        }
    }

    /* renamed from: com.pubmatic.sdk.video.player.e$e, reason: collision with other inner class name */
    public class RunnableC0019e implements Runnable {
        final /* synthetic */ int a;

        public RunnableC0019e(int i) {
            this.a = i;
        }

        @Override // java.lang.Runnable
        public void run() {
            if (C4070e.this.a != null) {
                C4070e.this.a.onBufferUpdate(this.a);
            }
        }
    }

    /* renamed from: com.pubmatic.sdk.video.player.e$f */
    public class f implements Runnable {
        public f() {
        }

        @Override // java.lang.Runnable
        public void run() {
            C4070e.this.h();
            if (C4070e.this.a != null) {
                C4070e.this.a.onCompletion();
            }
        }
    }

    /* renamed from: com.pubmatic.sdk.video.player.e$g */
    public class g implements Runnable {
        public g() {
        }

        @Override // java.lang.Runnable
        public void run() {
            if (C4070e.this.a != null) {
                C4070e.this.a.onStart();
            }
        }
    }

    /* renamed from: com.pubmatic.sdk.video.player.e$h */
    public class h implements Runnable {
        public h() {
        }

        @Override // java.lang.Runnable
        public void run() {
            if (C4070e.this.a != null) {
                C4070e.this.a.onPrepared();
            }
        }
    }

    /* renamed from: com.pubmatic.sdk.video.player.e$i */
    public class i extends HandlerThread {
        final /* synthetic */ String a;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public i(String str, String str2) {
            super(str);
            this.a = str2;
        }

        @Override // android.os.HandlerThread
        public void onLooperPrepared() {
            C4070e.this.c = new Handler(getLooper());
            C4070e.this.a(this.a);
        }
    }

    /* renamed from: com.pubmatic.sdk.video.player.e$j */
    public class j implements com.pubmatic.sdk.common.utility.k {
        public j() {
        }

        @Override // com.pubmatic.sdk.common.utility.k
        public void onTimeout() {
            if (C4070e.this.a != null) {
                C4070e.this.a.onFailure(-1, "MEDIA_FILE_TIMEOUT_ERROR");
            }
            C4070e.this.b();
        }
    }

    /* renamed from: com.pubmatic.sdk.video.player.e$k */
    public class k implements com.pubmatic.sdk.common.utility.k {
        public k() {
        }

        @Override // com.pubmatic.sdk.common.utility.k
        public void onTimeout() {
            C4070e.this.e.post(new y(this));
            C4070e.this.a(new z(this));
        }
    }

    /* renamed from: com.pubmatic.sdk.video.player.e$l */
    public class l implements com.pubmatic.sdk.common.utility.k {
        public l() {
        }

        @Override // com.pubmatic.sdk.common.utility.k
        public void onTimeout() {
            C4070e.this.a(new B(this));
        }
    }

    /* renamed from: com.pubmatic.sdk.video.player.e$m */
    public class m implements Runnable {
        final /* synthetic */ int a;
        final /* synthetic */ String b;

        public m(int i, String str) {
            this.a = i;
            this.b = str;
        }

        @Override // java.lang.Runnable
        public void run() {
            if (C4070e.this.a != null) {
                C4070e.this.a.onFailure(this.a, this.b);
            }
        }
    }

    /* renamed from: com.pubmatic.sdk.video.player.e$n */
    public class n implements Runnable {
        final /* synthetic */ String a;

        public n(String str) {
            this.a = str;
        }

        @Override // java.lang.Runnable
        public void run() {
            String message;
            int i;
            C4070e.this.a();
            try {
                if (C4070e.this.b != null) {
                    C4070e.this.b.setDataSource(this.a);
                    C4070e.this.d();
                    C4070e.this.b.prepare();
                }
            } catch (IOException e) {
                message = e.getMessage();
                if (message != null) {
                    i = -1004;
                    C4070e.this.a(i, message);
                }
            } catch (Exception e2) {
                message = e2.getMessage();
                if (message != null) {
                    i = 1;
                    C4070e.this.a(i, message);
                }
            }
        }
    }

    /* renamed from: com.pubmatic.sdk.video.player.e$o */
    public class o implements Runnable {
        public o() {
        }

        @Override // java.lang.Runnable
        public void run() throws IllegalStateException {
            if (C4070e.this.b != null) {
                C4070e.this.b.setSurface(null);
                C4070e.this.b.stop();
                C4070e.this.b.release();
                C4070e.this.b = null;
            }
            C4070e.this.d.quitSafely();
        }
    }

    /* renamed from: com.pubmatic.sdk.video.player.e$p */
    public class p implements Runnable {
        public p() {
        }

        @Override // java.lang.Runnable
        public void run() throws IllegalStateException {
            if (C4070e.this.b != null) {
                C4070e.this.b.start();
            }
            C4070e.this.e.post(new C(this));
        }
    }

    /* renamed from: com.pubmatic.sdk.video.player.e$q */
    public class q implements Runnable {
        public q() {
        }

        @Override // java.lang.Runnable
        public void run() throws IllegalStateException {
            if (C4070e.this.b != null) {
                C4070e.this.b.pause();
            }
            C4070e.this.e.post(new D(this));
        }
    }

    public C4070e(@NonNull String str, @NonNull Handler handler) {
        this.e = handler;
        i iVar = new i("POBMediaPlayer", str);
        this.d = iVar;
        iVar.start();
    }

    private String a(int i2) {
        return i2 != -1010 ? i2 != -1007 ? i2 != -1004 ? i2 != -110 ? "MEDIA_ERROR_UNKNOWN" : "MEDIA_ERROR_TIMED_OUT" : "MEDIA_ERROR_IO" : "MEDIA_ERROR_MALFORMED" : "MEDIA_ERROR_UNSUPPORTED";
    }

    @Override // com.pubmatic.sdk.video.player.h
    public void destroy() {
        b();
    }

    @Override // com.pubmatic.sdk.video.player.h
    public int getDuration() {
        return this.n;
    }

    @Override // com.pubmatic.sdk.video.player.h
    public int getVideoHeight() {
        return this.m;
    }

    @Override // com.pubmatic.sdk.video.player.h
    public int getVideoWidth() {
        return this.l;
    }

    @Override // android.media.MediaPlayer.OnBufferingUpdateListener
    public void onBufferingUpdate(MediaPlayer mediaPlayer, int i2) {
        g();
        this.e.post(new RunnableC0019e(i2));
    }

    @Override // android.media.MediaPlayer.OnCompletionListener
    public void onCompletion(MediaPlayer mediaPlayer) {
        this.e.post(new f());
    }

    @Override // android.media.MediaPlayer.OnErrorListener
    public boolean onError(MediaPlayer mediaPlayer, int i2, int i3) {
        return a(i3, a(i3));
    }

    @Override // android.media.MediaPlayer.OnInfoListener
    public boolean onInfo(MediaPlayer mediaPlayer, int i2, int i3) {
        POBLog.info("POBMediaPlayer", d0.p("onInfo what: ", i2, ", extra:", i3), new Object[0]);
        if (i2 == 3) {
            this.e.post(new g());
            return true;
        }
        if (i2 == 701) {
            c();
        } else if (i2 == 702) {
            f();
        } else if (i3 == -1004) {
            return a(i3, a(i3));
        }
        return false;
    }

    @Override // android.media.MediaPlayer.OnPreparedListener
    public void onPrepared(MediaPlayer mediaPlayer) {
        g();
        if (mediaPlayer != null) {
            this.n = mediaPlayer.getDuration();
        }
        this.e.post(new h());
    }

    @Override // com.pubmatic.sdk.video.player.h
    public void onSurfaceCreated(@NonNull Surface surface) {
        a(new c(surface));
    }

    @Override // com.pubmatic.sdk.video.player.h
    public void onSurfaceDestroyed(@NonNull Surface surface) {
        a(new d());
    }

    @Override // android.media.MediaPlayer.OnVideoSizeChangedListener
    public void onVideoSizeChanged(MediaPlayer mediaPlayer, int i2, int i3) {
        this.l = i2;
        this.m = i3;
    }

    @Override // com.pubmatic.sdk.video.player.h
    public void pause() {
        h();
        a(new q());
    }

    @Override // com.pubmatic.sdk.video.player.h
    public void setPlayerListener(@NonNull com.pubmatic.sdk.video.player.g gVar) {
        this.a = gVar;
    }

    @Override // com.pubmatic.sdk.video.player.h
    public void setPrepareTimeout(int i2) {
        this.i = i2;
    }

    @Override // com.pubmatic.sdk.video.player.h
    public void setStallTimeout(int i2) {
        this.k = i2;
    }

    @Override // com.pubmatic.sdk.video.player.h
    public void setVolume(int i2, int i3) {
        a(new b(i2, i3));
    }

    @Override // com.pubmatic.sdk.video.player.h
    public void start() {
        e();
        a(new p());
    }

    @Override // com.pubmatic.sdk.video.player.h
    public void stop() {
        a(new a());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void b() {
        this.a = null;
        h();
        g();
        f();
        a(new o());
    }

    private void c() {
        if (this.j == null) {
            com.pubmatic.sdk.common.utility.l lVar = new com.pubmatic.sdk.common.utility.l(new k());
            this.j = lVar;
            lVar.start(this.k);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void d() {
        com.pubmatic.sdk.common.utility.l lVar = new com.pubmatic.sdk.common.utility.l(new j());
        this.h = lVar;
        lVar.start(this.i);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void e() {
        if (this.f == null) {
            com.pubmatic.sdk.common.utility.l lVar = new com.pubmatic.sdk.common.utility.l(new l());
            this.f = lVar;
            lVar.startAtFixedRate(0L, 500L);
        }
    }

    private void f() {
        com.pubmatic.sdk.common.utility.l lVar = this.j;
        if (lVar != null) {
            lVar.cancel();
            this.j = null;
        }
    }

    private void g() {
        com.pubmatic.sdk.common.utility.l lVar = this.h;
        if (lVar != null) {
            lVar.cancel();
            this.h = null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void h() {
        com.pubmatic.sdk.common.utility.l lVar = this.f;
        if (lVar != null) {
            lVar.cancel();
            this.f = null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void a() {
        MediaPlayer mediaPlayer = new MediaPlayer();
        this.b = mediaPlayer;
        mediaPlayer.setOnPreparedListener(this);
        this.b.setOnCompletionListener(this);
        this.b.setOnBufferingUpdateListener(this);
        this.b.setAudioStreamType(3);
        this.b.setOnErrorListener(this);
        this.b.setOnInfoListener(this);
        this.b.setOnVideoSizeChangedListener(this);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void a(@NonNull Runnable runnable) {
        if (this.d.isAlive()) {
            Handler handler = this.c;
            if (handler != null) {
                handler.post(runnable);
                return;
            } else {
                POBLog.error("POBMediaPlayer", "mediaPlayerHandler is null", new Object[0]);
                return;
            }
        }
        POBLog.error("POBMediaPlayer", "Handler thread is dead already", new Object[0]);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean a(int i2, @NonNull String str) {
        g();
        POBLog.error("POBMediaPlayer", "errorCode: " + i2 + ", errorMsg:" + str, new Object[0]);
        this.e.post(new m(i2, str));
        return true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void a(@NonNull String str) {
        a(new n(str));
    }
}
