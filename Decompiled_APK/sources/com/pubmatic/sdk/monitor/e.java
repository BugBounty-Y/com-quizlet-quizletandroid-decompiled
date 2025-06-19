package com.pubmatic.sdk.monitor;

import android.R;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.graphics.Point;
import android.graphics.drawable.GradientDrawable;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.RelativeLayout;
import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.utility.o;

/* loaded from: classes2.dex */
public class e extends RelativeLayout implements View.OnTouchListener {
    float a;
    float b;
    float c;
    float d;
    Point e;
    private ViewGroup f;
    private f g;

    @NonNull
    RelativeLayout h;

    public class a implements View.OnClickListener {
        public a() {
        }

        @Override // android.view.View.OnClickListener
        public void onClick(View view) {
            e.this.f.removeView(e.this);
            if (e.this.g != null) {
                e.this.g.a();
            }
        }
    }

    public e(Activity activity, Point point) {
        super(activity);
        this.e = point;
        this.f = (ViewGroup) activity.findViewById(R.id.content);
        a();
    }

    public Point getTouchPointLocation() {
        Point point = new Point();
        point.set((int) this.h.getX(), (int) this.h.getY());
        return point;
    }

    @Override // android.view.View.OnTouchListener
    public boolean onTouch(View view, MotionEvent motionEvent) {
        f fVar;
        int actionMasked = motionEvent.getActionMasked();
        if (actionMasked == 0) {
            this.c = view.getX();
            this.d = view.getY();
            this.a = this.c - motionEvent.getRawX();
            this.b = this.d - motionEvent.getRawY();
        } else if (actionMasked == 1) {
            float x = view.getX();
            float y = view.getY();
            if (Math.abs(x - this.c) <= 20.0f && Math.abs(y - this.d) <= 20.0f && (fVar = this.g) != null) {
                fVar.b();
            }
        } else {
            if (actionMasked != 2) {
                return false;
            }
            view.setY(motionEvent.getRawY() + this.b);
            view.setX(motionEvent.getRawX() + this.a);
        }
        return true;
    }

    public void setListener(f fVar) {
        this.g = fVar;
    }

    @SuppressLint({"ClickableViewAccessibility"})
    private void a() {
        RelativeLayout relativeLayout = (RelativeLayout) ((LayoutInflater) getContext().getSystemService("layout_inflater")).inflate(k.pob_monitor_view, (ViewGroup) null);
        this.h = relativeLayout;
        Button button = (Button) relativeLayout.findViewById(j.pob_monitor_floating_btn);
        GradientDrawable gradientDrawable = new GradientDrawable();
        gradientDrawable.setCornerRadius(o.convertDpToPixel(16));
        gradientDrawable.setColor(getResources().getColor(i.pob_monitor_background));
        button.setBackground(gradientDrawable);
        Button button2 = (Button) this.h.findViewById(j.pob_monitor_close_btn);
        button2.setOnClickListener(new a());
        GradientDrawable gradientDrawable2 = new GradientDrawable();
        gradientDrawable2.setShape(1);
        gradientDrawable2.setColor(getResources().getColor(i.pob_monitor_close_background));
        button2.setBackground(gradientDrawable2);
        this.h.setX(this.e.x);
        this.h.setY(this.e.y);
        this.h.setOnTouchListener(this);
        RelativeLayout.LayoutParams layoutParams = new RelativeLayout.LayoutParams(-2, -2);
        Point point = this.e;
        if (point.x == 0 && point.y == 0) {
            layoutParams.addRule(12);
            layoutParams.addRule(11);
            layoutParams.rightMargin = o.convertDpToPixel(80);
            layoutParams.bottomMargin = o.convertDpToPixel(100);
        }
        addView(this.h, layoutParams);
        this.f.addView(this, 0, new RelativeLayout.LayoutParams(-1, -1));
    }
}
