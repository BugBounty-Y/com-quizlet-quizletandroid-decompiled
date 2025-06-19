package com.pubmatic.sdk.video.player;

import android.R;
import android.annotation.SuppressLint;
import android.content.Context;
import android.content.res.Resources;
import android.graphics.PorterDuff;
import android.graphics.drawable.GradientDrawable;
import android.view.MotionEvent;
import android.view.View;
import android.widget.FrameLayout;
import android.widget.ImageButton;
import android.widget.SeekBar;
import androidx.annotation.NonNull;

/* loaded from: classes2.dex */
public class t extends i {
    private s a;

    @NonNull
    private SeekBar b;

    @NonNull
    private ImageButton c;

    @NonNull
    private Resources d;

    public class a implements View.OnTouchListener {
        public a() {
        }

        @Override // android.view.View.OnTouchListener
        public boolean onTouch(View view, MotionEvent motionEvent) {
            return true;
        }
    }

    public class b implements View.OnClickListener {
        public b() {
        }

        @Override // android.view.View.OnClickListener
        public void onClick(View view) {
            if (t.this.a != null) {
                t.this.a(!r2.a.isMute());
                t tVar = t.this;
                tVar.b(tVar.a.isMute());
            }
        }
    }

    public t(@NonNull Context context) {
        super(context);
        this.d = getResources();
        this.b = c();
        this.c = b();
        a();
    }

    @SuppressLint({"ClickableViewAccessibility"})
    private SeekBar c() {
        SeekBar seekBar = new SeekBar(getContext());
        seekBar.setPadding(0, 0, 0, com.pubmatic.sdk.common.utility.o.convertDpToPixel(1));
        seekBar.setThumb(null);
        seekBar.getProgressDrawable().setColorFilter(this.d.getColor(R.color.holo_blue_light), PorterDuff.Mode.SRC_ATOP);
        seekBar.setOnTouchListener(new a());
        return seekBar;
    }

    @Override // com.pubmatic.sdk.video.player.i, com.pubmatic.sdk.video.player.u
    public void onMute(boolean z) {
    }

    @Override // com.pubmatic.sdk.video.player.i, com.pubmatic.sdk.video.player.u
    public void onPause() {
    }

    @Override // com.pubmatic.sdk.video.player.i, com.pubmatic.sdk.video.player.u
    public void onProgressUpdate(int i) {
        this.b.setProgress(i);
    }

    @Override // com.pubmatic.sdk.video.player.i, com.pubmatic.sdk.video.player.u
    public void onResume() {
    }

    @Override // com.pubmatic.sdk.video.player.i, com.pubmatic.sdk.video.player.u
    public void onStart() {
        s sVar = this.a;
        if (sVar != null) {
            this.b.setMax(sVar.getMediaDuration());
            b(this.a.isMute());
        }
    }

    @Override // com.pubmatic.sdk.video.player.i
    public void setVideoPlayerEvents(@NonNull s sVar) {
        this.a = sVar;
    }

    private ImageButton b() {
        ImageButton imageButton = new ImageButton(getContext());
        imageButton.setId(com.pubmatic.sdk.video.h.pob_mute_btn);
        GradientDrawable gradientDrawable = new GradientDrawable();
        gradientDrawable.setShape(1);
        gradientDrawable.setColor(this.d.getColor(com.pubmatic.sdk.video.e.pob_controls_background_color));
        gradientDrawable.setStroke(this.d.getDimensionPixelOffset(com.pubmatic.sdk.video.f.pob_control_stroke_width), this.d.getColor(com.pubmatic.sdk.video.e.pob_controls_stroke_color));
        gradientDrawable.setAlpha(this.d.getInteger(com.pubmatic.sdk.video.i.pob_controls_alpha));
        imageButton.setBackground(gradientDrawable);
        imageButton.setPadding(0, 0, 0, 0);
        imageButton.setImageResource(com.pubmatic.sdk.video.g.pob_ic_volume_up_black_24dp);
        imageButton.setOnClickListener(new b());
        return imageButton;
    }

    private void a() {
        FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(-1, this.d.getDimensionPixelOffset(com.pubmatic.sdk.video.f.pob_seek_bar_height));
        layoutParams.gravity = 80;
        layoutParams.leftMargin = this.d.getDimensionPixelOffset(com.pubmatic.sdk.video.f.pob_seek_left_margin);
        layoutParams.rightMargin = this.d.getDimensionPixelOffset(com.pubmatic.sdk.video.f.pob_seek_right_margin);
        addView(this.b, layoutParams);
        FrameLayout.LayoutParams layoutParams2 = new FrameLayout.LayoutParams(this.d.getDimensionPixelOffset(com.pubmatic.sdk.video.f.pob_control_width), this.d.getDimensionPixelOffset(com.pubmatic.sdk.video.f.pob_control_height));
        layoutParams2.gravity = 8388691;
        layoutParams2.bottomMargin = this.d.getDimensionPixelOffset(com.pubmatic.sdk.video.f.pob_mute_button_bottom_margin);
        layoutParams2.leftMargin = this.d.getDimensionPixelOffset(com.pubmatic.sdk.video.f.pob_mute_button_left_margin);
        addView(this.c, layoutParams2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void a(boolean z) {
        s sVar = this.a;
        if (sVar != null) {
            if (z) {
                sVar.mute();
            } else {
                sVar.unMute();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void b(boolean z) {
        if (z) {
            this.c.setImageResource(com.pubmatic.sdk.video.g.pob_ic_volume_off_black_24dp);
        } else {
            this.c.setImageResource(com.pubmatic.sdk.video.g.pob_ic_volume_up_black_24dp);
        }
    }
}
