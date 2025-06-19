package com.pubmatic.sdk.webrendering.mraid;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.res.Configuration;
import android.media.MediaPlayer;
import android.net.Uri;
import android.os.Bundle;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageButton;
import android.widget.MediaController;
import android.widget.VideoView;
import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.log.POBLog;
import java.util.ArrayList;
import java.util.List;

/* loaded from: classes2.dex */
public class POBVideoPlayerActivity extends Activity {
    public static final String ACTION_FINISH = "com.pubmatic.sdk.webrendering.mraid.POBVideoPlayerActivity.finish";
    public static final String ALLOW_ORIENTATION_KEY = "AllowOrientationChange";
    public static final String FORCE_ORIENTATION_KEY = "ForceOrientation";
    public static final String MSG_VIDEO_PLAYER_EMPTY_URL = "Can't launch video player due to null or empty value of URL";
    private static List<g> a;
    private MediaController b;
    private VideoView c;
    private int d;
    private boolean e;
    private BroadcastReceiver f;
    private int g;

    public class a extends BroadcastReceiver {
        public a() {
        }

        @Override // android.content.BroadcastReceiver
        public void onReceive(Context context, Intent intent) {
            if (intent == null || !POBVideoPlayerActivity.ACTION_FINISH.equals(intent.getAction())) {
                return;
            }
            POBVideoPlayerActivity.this.finish();
        }
    }

    public class b implements View.OnClickListener {
        public b() {
        }

        @Override // android.view.View.OnClickListener
        public void onClick(View view) {
            POBVideoPlayerActivity.this.finish();
        }
    }

    public class c implements MediaPlayer.OnCompletionListener {
        public c() {
        }

        @Override // android.media.MediaPlayer.OnCompletionListener
        public void onCompletion(MediaPlayer mediaPlayer) {
            POBVideoPlayerActivity.this.e = true;
        }
    }

    private void b() {
        List<g> list = a;
        if (list != null) {
            for (g gVar : list) {
                if (this.g == gVar.hashCode()) {
                    gVar.onDismiss();
                    a(gVar);
                    return;
                }
            }
        }
    }

    private void c() {
        List<g> list = a;
        if (list != null) {
            for (g gVar : list) {
                if (this.g == gVar.hashCode()) {
                    gVar.onStart();
                    return;
                }
            }
        }
    }

    private void d() {
        VideoView videoView = this.c;
        if (videoView == null) {
            POBLog.debug("POBVideoPlayerActivity", "Unable to pause video, VideoView not available.", new Object[0]);
            return;
        }
        videoView.pause();
        this.d = this.c.getCurrentPosition();
        POBLog.debug("POBVideoPlayerActivity", "VideoView visibility is false. Seeked position =" + this.d, new Object[0]);
    }

    private void e() {
        if (this.e) {
            POBLog.debug("POBVideoPlayerActivity", "Video Ad is completed", new Object[0]);
            return;
        }
        VideoView videoView = this.c;
        if (videoView == null) {
            POBLog.debug("POBVideoPlayerActivity", "Unable to resume video, VideoView not available.", new Object[0]);
        } else {
            if (videoView.isPlaying()) {
                this.c.seekTo(this.d);
                return;
            }
            POBLog.debug("POBVideoPlayerActivity", "VideoView visibility is false. Seeked position =" + this.d, new Object[0]);
        }
    }

    public static void startNewActivity(@NonNull Context context, @NonNull String str, Bundle bundle, @NonNull g gVar) {
        if (a == null) {
            a = new ArrayList();
        }
        a.add(gVar);
        Intent intent = new Intent(context, (Class<?>) POBVideoPlayerActivity.class);
        intent.addFlags(268435456);
        intent.putExtra("URL", str);
        intent.putExtra("listener_hash_code", gVar.hashCode());
        intent.putExtra("bundle_extra", bundle);
        context.startActivity(intent);
    }

    @Override // android.app.Activity, android.content.ComponentCallbacks
    public void onConfigurationChanged(@NonNull Configuration configuration) {
        super.onConfigurationChanged(configuration);
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:15:0x0047  */
    @Override // android.app.Activity
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void onCreate(android.os.Bundle r8) {
        /*
            r7 = this;
            r0 = -1
            r1 = 1
            super.onCreate(r8)
            android.content.Intent r8 = r7.getIntent()
            java.lang.String r2 = "URL"
            java.lang.String r2 = r8.getStringExtra(r2)
            boolean r3 = com.pubmatic.sdk.common.utility.o.isNullOrEmpty(r2)
            r4 = 0
            if (r3 == 0) goto L22
            java.lang.Object[] r3 = new java.lang.Object[r4]
            java.lang.String r5 = "POBVideoPlayerActivity"
            java.lang.String r6 = "Can't launch video player due to null or empty value of URL"
            com.pubmatic.sdk.common.log.POBLog.error(r5, r6, r3)
            r7.finish()
        L22:
            java.lang.String r3 = "bundle_extra"
            android.os.Bundle r8 = r8.getBundleExtra(r3)
            if (r8 == 0) goto L37
            java.lang.String r3 = "ForceOrientation"
            java.lang.String r3 = r8.getString(r3)
            java.lang.String r5 = "AllowOrientationChange"
            boolean r8 = r8.getBoolean(r5, r1)
            goto L39
        L37:
            r3 = 0
            r8 = r1
        L39:
            if (r8 != 0) goto L89
            if (r3 == 0) goto L3e
            goto L40
        L3e:
            java.lang.String r3 = "none"
        L40:
            int r8 = r3.hashCode()
            switch(r8) {
                case -1700437898: goto L6a;
                case -31410088: goto L5f;
                case 729267099: goto L54;
                case 1430647483: goto L49;
                default: goto L47;
            }
        L47:
            r8 = r0
            goto L74
        L49:
            java.lang.String r8 = "landscape"
            boolean r8 = r3.equals(r8)
            if (r8 != 0) goto L52
            goto L47
        L52:
            r8 = 3
            goto L74
        L54:
            java.lang.String r8 = "portrait"
            boolean r8 = r3.equals(r8)
            if (r8 != 0) goto L5d
            goto L47
        L5d:
            r8 = 2
            goto L74
        L5f:
            java.lang.String r8 = "reverse_portrait"
            boolean r8 = r3.equals(r8)
            if (r8 != 0) goto L68
            goto L47
        L68:
            r8 = r1
            goto L74
        L6a:
            java.lang.String r8 = "sensor_landscape"
            boolean r8 = r3.equals(r8)
            if (r8 != 0) goto L73
            goto L47
        L73:
            r8 = r4
        L74:
            switch(r8) {
                case 0: goto L85;
                case 1: goto L80;
                case 2: goto L7c;
                case 3: goto L78;
                default: goto L77;
            }
        L77:
            goto L89
        L78:
            r7.setRequestedOrientation(r4)
            goto L89
        L7c:
            r7.setRequestedOrientation(r1)
            goto L89
        L80:
            r8 = 7
            r7.setRequestedOrientation(r8)
            goto L89
        L85:
            r8 = 6
            r7.setRequestedOrientation(r8)
        L89:
            android.view.View r8 = r7.a(r2)
            android.view.View r8 = r7.a(r8, r0, r0)
            r7.setContentView(r8)
            com.pubmatic.sdk.webrendering.mraid.POBVideoPlayerActivity$a r8 = new com.pubmatic.sdk.webrendering.mraid.POBVideoPlayerActivity$a
            r8.<init>()
            r7.f = r8
            int r0 = android.os.Build.VERSION.SDK_INT
            r1 = 33
            java.lang.String r2 = "com.pubmatic.sdk.webrendering.mraid.POBVideoPlayerActivity.finish"
            if (r0 < r1) goto Lad
            android.content.IntentFilter r0 = new android.content.IntentFilter
            r0.<init>(r2)
            r1 = 4
            r7.registerReceiver(r8, r0, r1)
            goto Lb5
        Lad:
            android.content.IntentFilter r0 = new android.content.IntentFilter
            r0.<init>(r2)
            r7.registerReceiver(r8, r0)
        Lb5:
            android.content.Intent r8 = r7.getIntent()
            java.lang.String r0 = "listener_hash_code"
            int r8 = r8.getIntExtra(r0, r4)
            r7.g = r8
            r7.c()
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.pubmatic.sdk.webrendering.mraid.POBVideoPlayerActivity.onCreate(android.os.Bundle):void");
    }

    @Override // android.app.Activity
    public void onDestroy() {
        super.onDestroy();
        a();
        unregisterReceiver(this.f);
        this.f = null;
        b();
    }

    @Override // android.app.Activity
    public void onPause() {
        super.onPause();
        d();
    }

    @Override // android.app.Activity
    public void onResume() {
        super.onResume();
        e();
    }

    private void a(@NonNull g gVar) {
        List<g> list = a;
        if (list != null) {
            list.remove(gVar);
            if (a.isEmpty()) {
                a = null;
            }
        }
    }

    private void a() {
        VideoView videoView = this.c;
        if (videoView != null) {
            videoView.suspend();
        }
        this.c = null;
        this.b = null;
    }

    @NonNull
    private View a(View view, int i, int i2) {
        FrameLayout frameLayout = new FrameLayout(this);
        FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(i, i2);
        layoutParams.gravity = 17;
        layoutParams.setMargins(0, 0, 0, 0);
        if (view != null) {
            frameLayout.addView(view, layoutParams);
        }
        ImageButton imageButtonCreateSkipButton = com.pubmatic.sdk.webrendering.a.createSkipButton(this, com.pubmatic.sdk.webrendering.e.pob_close_btn, com.pubmatic.sdk.webrendering.d.pob_ic_close_black_24dp);
        frameLayout.addView(imageButtonCreateSkipButton);
        imageButtonCreateSkipButton.setOnClickListener(new b());
        return frameLayout;
    }

    private View a(@NonNull String str) {
        this.c = new VideoView(this);
        if (this.b == null) {
            MediaController mediaController = new MediaController(this);
            this.b = mediaController;
            mediaController.setMediaPlayer(this.c);
        }
        this.c.setMediaController(this.b);
        this.b.setAnchorView(this.c);
        this.c.setOnCompletionListener(new c());
        this.c.setVideoURI(Uri.parse(str));
        this.c.start();
        return this.c;
    }
}
