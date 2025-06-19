package com.pubmatic.sdk.video.player;

import android.R;
import android.content.Context;
import android.content.res.Configuration;
import android.os.Handler;
import android.os.Looper;
import android.view.SurfaceHolder;
import android.view.SurfaceView;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.log.POBLog;
import com.pubmatic.sdk.video.c;

/* loaded from: classes2.dex */
public class v extends FrameLayout implements s, SurfaceHolder.Callback, g {
    private int a;

    @NonNull
    private final SurfaceView b;
    private h c;
    private u d;
    private i e;
    private boolean f;
    private boolean g;

    @NonNull
    private r h;
    private boolean i;

    @NonNull
    private final View.OnClickListener j;

    public class a implements View.OnClickListener {
        public a() {
        }

        @Override // android.view.View.OnClickListener
        public void onClick(View view) {
            if (v.this.d != null) {
                v.this.d.onClick();
            }
        }
    }

    public class b implements Runnable {
        public b() {
        }

        @Override // java.lang.Runnable
        public void run() {
            if (v.this.c != null) {
                v vVar = v.this;
                vVar.setVideoSize(vVar.c);
            }
        }
    }

    public v(@NonNull Context context) {
        super(context);
        this.a = c.a.DEFAULT_MEDIA_URI_TIMEOUT;
        this.j = new a();
        this.b = new SurfaceView(getContext());
        a();
        this.h = r.UNKNOWN;
    }

    private void setPlayerState(@NonNull r rVar) {
        this.h = rVar;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setVideoSize(@NonNull h hVar) {
        float videoWidth = hVar.getVideoWidth() / hVar.getVideoHeight();
        int width = getWidth();
        int height = getHeight();
        float f = width;
        float f2 = height;
        float f3 = f / f2;
        ViewGroup.LayoutParams layoutParams = this.b.getLayoutParams();
        if (videoWidth > f3) {
            layoutParams.width = width;
            layoutParams.height = (int) (f / videoWidth);
        } else {
            layoutParams.width = (int) (videoWidth * f2);
            layoutParams.height = height;
        }
        this.b.setLayoutParams(layoutParams);
    }

    @Override // com.pubmatic.sdk.video.player.s
    public void destroy() {
        removeAllViews();
        h hVar = this.c;
        if (hVar != null) {
            hVar.destroy();
            this.c = null;
        }
        this.d = null;
        this.e = null;
    }

    @Override // com.pubmatic.sdk.video.player.s
    public i getControllerView() {
        return this.e;
    }

    @Override // com.pubmatic.sdk.video.player.s
    public int getMediaDuration() {
        h hVar = this.c;
        if (hVar != null) {
            return hVar.getDuration();
        }
        return 0;
    }

    @Override // com.pubmatic.sdk.video.player.s
    @NonNull
    public r getPlayerState() {
        return this.h;
    }

    @Override // com.pubmatic.sdk.video.player.s
    public boolean isMute() {
        return this.g;
    }

    @Override // com.pubmatic.sdk.video.player.s
    public void load(@NonNull String str) {
        C4070e c4070e = new C4070e(str, new Handler(Looper.getMainLooper()));
        this.c = c4070e;
        c4070e.setPlayerListener(this);
        this.c.setPrepareTimeout(this.a);
        this.c.setStallTimeout(s.MAX_STALLING_TIMEOUT);
        this.i = false;
    }

    @Override // com.pubmatic.sdk.video.player.s
    public void mute() {
        u uVar = this.d;
        if (uVar != null) {
            uVar.onMute(true);
        }
        h hVar = this.c;
        if (hVar == null) {
            POBLog.warn("POBVideoPlayerView", "Media player is null", new Object[0]);
        } else {
            this.g = true;
            hVar.setVolume(0, 0);
        }
    }

    @Override // com.pubmatic.sdk.video.player.g
    public void onBufferUpdate(int i) {
        u uVar = this.d;
        if (uVar != null) {
            uVar.onBufferUpdate(i);
        }
    }

    @Override // com.pubmatic.sdk.video.player.g
    public void onCompletion() {
        setPlayerState(r.COMPLETE);
        u uVar = this.d;
        if (uVar != null) {
            uVar.onProgressUpdate(getMediaDuration());
            this.d.onCompletion();
        }
    }

    @Override // android.view.View
    public void onConfigurationChanged(Configuration configuration) {
        super.onConfigurationChanged(configuration);
        POBLog.info("POBVideoPlayerView", "onConfigurationChanged", new Object[0]);
        postDelayed(new b(), 5L);
    }

    @Override // com.pubmatic.sdk.video.player.g
    public void onFailure(int i, @NonNull String str) {
        a(i, str);
    }

    @Override // com.pubmatic.sdk.video.player.g
    public void onPause() {
        u uVar = this.d;
        if (uVar != null) {
            uVar.onPause();
        }
        i iVar = this.e;
        if (iVar != null) {
            iVar.onPause();
        }
    }

    @Override // com.pubmatic.sdk.video.player.g
    public void onPrepared() {
        h hVar;
        if (this.d != null) {
            if (this.g && (hVar = this.c) != null) {
                hVar.setVolume(0, 0);
            }
            setPlayerState(r.LOADED);
            this.d.onReadyToPlay(this);
        }
    }

    @Override // com.pubmatic.sdk.video.player.g
    public void onProgressUpdate(int i) {
        a(i);
    }

    @Override // com.pubmatic.sdk.video.player.g
    public void onResume() {
        u uVar = this.d;
        if (uVar != null && this.h == r.PAUSED) {
            uVar.onResume();
        }
        setPlayerState(r.PLAYING);
    }

    @Override // com.pubmatic.sdk.video.player.g
    public void onStart() {
        if (this.i) {
            return;
        }
        b();
        this.i = true;
    }

    @Override // com.pubmatic.sdk.video.player.g
    public void onStop() {
        setPlayerState(r.STOPPED);
    }

    @Override // com.pubmatic.sdk.video.player.s
    public void pause() {
        if (this.c != null && this.h == r.PLAYING) {
            setPlayerState(r.PAUSED);
            this.c.pause();
        } else {
            POBLog.warn("POBVideoPlayerView", "mediaPlayer :" + this.c, new Object[0]);
        }
    }

    @Override // com.pubmatic.sdk.video.player.s
    public void play() {
        h hVar = this.c;
        if (hVar == null || this.h == r.ERROR) {
            POBLog.warn("POBVideoPlayerView", "mediaPlayer :null", new Object[0]);
        } else {
            hVar.start();
        }
    }

    @Override // com.pubmatic.sdk.video.player.s
    public void playOnMute(boolean z) {
        this.g = z;
    }

    @Override // com.pubmatic.sdk.video.player.s
    public void setAutoPlayOnForeground(boolean z) {
        this.f = z;
    }

    @Override // com.pubmatic.sdk.video.player.s
    public void setControllerView(@NonNull i iVar, @NonNull FrameLayout.LayoutParams layoutParams) {
        this.e = iVar;
        iVar.setVideoPlayerEvents(this);
        addView(iVar, layoutParams);
    }

    public void setFSCEnabled(boolean z) {
        setOnClickListener(z ? this.j : null);
    }

    @Override // com.pubmatic.sdk.video.player.s
    public void setListener(@NonNull u uVar) {
        this.d = uVar;
    }

    @Override // com.pubmatic.sdk.video.player.s
    public void setPrepareTimeout(int i) {
        this.a = i;
    }

    @Override // com.pubmatic.sdk.video.player.s
    public void stop() {
        h hVar = this.c;
        if (hVar != null) {
            hVar.stop();
        }
    }

    @Override // android.view.SurfaceHolder.Callback
    public void surfaceChanged(@NonNull SurfaceHolder surfaceHolder, int i, int i2, int i3) {
    }

    @Override // android.view.SurfaceHolder.Callback
    public void surfaceCreated(@NonNull SurfaceHolder surfaceHolder) {
        h hVar = this.c;
        if (hVar == null || this.h == r.ERROR) {
            return;
        }
        setVideoSize(hVar);
        this.c.onSurfaceCreated(surfaceHolder.getSurface());
        if (!this.f || this.h == r.COMPLETE) {
            return;
        }
        play();
    }

    @Override // android.view.SurfaceHolder.Callback
    public void surfaceDestroyed(@NonNull SurfaceHolder surfaceHolder) {
        if (this.h != r.ERROR) {
            pause();
        }
        h hVar = this.c;
        if (hVar != null) {
            hVar.onSurfaceDestroyed(surfaceHolder.getSurface());
        }
    }

    @Override // com.pubmatic.sdk.video.player.s
    public void unMute() {
        u uVar = this.d;
        if (uVar != null) {
            uVar.onMute(false);
        }
        h hVar = this.c;
        if (hVar == null) {
            POBLog.warn("POBVideoPlayerView", "Media player is null", new Object[0]);
        } else {
            this.g = false;
            hVar.setVolume(1, 1);
        }
    }

    private void b() {
        i iVar = this.e;
        if (iVar != null) {
            iVar.onStart();
        }
        u uVar = this.d;
        if (uVar != null) {
            uVar.onStart();
        }
    }

    private void a() {
        this.b.getHolder().addCallback(this);
        FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(-1, -1);
        layoutParams.gravity = 17;
        addView(this.b, layoutParams);
        setBackgroundColor(getResources().getColor(R.color.black));
    }

    private void a(int i, @NonNull String str) {
        r rVar = this.h;
        r rVar2 = r.ERROR;
        if (rVar != rVar2) {
            setPlayerState(rVar2);
            POBLog.error("POBVideoPlayerView", "errorCode: " + i + ", errorMsg:" + str, new Object[0]);
            u uVar = this.d;
            if (uVar != null) {
                if (i != -1) {
                    i = -2;
                }
                uVar.onFailure(i, str);
            }
        }
    }

    private void a(int i) {
        if (this.c != null) {
            i iVar = this.e;
            if (iVar != null) {
                iVar.onProgressUpdate(i);
            }
            u uVar = this.d;
            if (uVar != null) {
                uVar.onProgressUpdate(i);
            }
        }
    }
}
