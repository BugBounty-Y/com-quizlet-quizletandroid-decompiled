package com.quizlet.features.achievements.achievement;

import android.view.GestureDetector;
import android.view.MotionEvent;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b extends GestureDetector.SimpleOnGestureListener {
    public final c a;
    public final c b;

    public b(c onSwipeDown, c onTap) {
        Intrinsics.checkNotNullParameter(onSwipeDown, "onSwipeDown");
        Intrinsics.checkNotNullParameter(onTap, "onTap");
        this.a = onSwipeDown;
        this.b = onTap;
    }

    @Override // android.view.GestureDetector.SimpleOnGestureListener, android.view.GestureDetector.OnGestureListener
    public final boolean onDown(MotionEvent e) {
        Intrinsics.checkNotNullParameter(e, "e");
        return true;
    }

    @Override // android.view.GestureDetector.SimpleOnGestureListener, android.view.GestureDetector.OnGestureListener
    public final boolean onScroll(MotionEvent motionEvent, MotionEvent secondEvent, float f, float f2) {
        Intrinsics.checkNotNullParameter(secondEvent, "secondEvent");
        if (motionEvent == null) {
            return false;
        }
        double degrees = Math.toDegrees((float) Math.atan2(motionEvent.getY() - secondEvent.getY(), motionEvent.getX() - secondEvent.getX()));
        if (-180.0d > degrees || degrees > 0.0d) {
            return false;
        }
        this.a.invoke();
        return true;
    }

    @Override // android.view.GestureDetector.SimpleOnGestureListener, android.view.GestureDetector.OnGestureListener
    public final boolean onSingleTapUp(MotionEvent p0) {
        Intrinsics.checkNotNullParameter(p0, "p0");
        this.b.invoke();
        return true;
    }
}
