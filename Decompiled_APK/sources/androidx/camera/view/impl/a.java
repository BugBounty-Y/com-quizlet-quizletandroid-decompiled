package androidx.camera.view.impl;

import android.view.GestureDetector;
import android.view.MotionEvent;
import com.google.android.gms.internal.mlkit_common.u;
import com.google.firebase.heartbeatinfo.e;
import com.perimeterx.mobile_sdk.doctor_app.ui.PXDoctorActivity;
import com.perimeterx.mobile_sdk.doctor_app.ui.c;
import com.quizlet.quizletandroid.ui.FullScreenOverlayActivity;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a extends GestureDetector.SimpleOnGestureListener {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ a(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // android.view.GestureDetector.SimpleOnGestureListener, android.view.GestureDetector.OnDoubleTapListener
    public boolean onDoubleTap(MotionEvent e) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(e, "e");
                e.getX();
                ((e) this.b).getClass();
                e.getY();
                return true;
            default:
                return super.onDoubleTap(e);
        }
    }

    @Override // android.view.GestureDetector.SimpleOnGestureListener, android.view.GestureDetector.OnGestureListener
    public boolean onDown(MotionEvent e) {
        switch (this.a) {
            case 1:
                Intrinsics.checkNotNullParameter(e, "e");
                return true;
            default:
                return super.onDown(e);
        }
    }

    @Override // android.view.GestureDetector.SimpleOnGestureListener, android.view.GestureDetector.OnGestureListener
    public boolean onFling(MotionEvent e1, MotionEvent e2, float f, float f2) {
        switch (this.a) {
            case 1:
                Intrinsics.checkNotNullParameter(e1, "e1");
                Intrinsics.checkNotNullParameter(e2, "e2");
                try {
                    float y = e2.getY() - e1.getY();
                    float x = e2.getX() - e1.getX();
                    float fAbs = Math.abs(x);
                    float fAbs2 = Math.abs(y);
                    c cVar = (c) this.b;
                    if (fAbs > fAbs2) {
                        if (Math.abs(x) <= 100.0f || Math.abs(f) <= 100.0f) {
                            return false;
                        }
                        if (x > DefinitionKt.NO_Float_VALUE) {
                            cVar.getClass();
                        } else {
                            cVar.getClass();
                        }
                    } else {
                        if (Math.abs(y) <= 100.0f || Math.abs(f2) <= 100.0f) {
                            return false;
                        }
                        if (y > DefinitionKt.NO_Float_VALUE) {
                            cVar.getClass();
                        } else {
                            cVar.getClass();
                            com.braze.ui.inappmessage.listeners.a aVar = new com.braze.ui.inappmessage.listeners.a(27);
                            u uVar = PXDoctorActivity.e;
                            cVar.b.r(false, aVar);
                        }
                    }
                    return true;
                } catch (Exception unused) {
                    return false;
                }
            default:
                return super.onFling(e1, e2, f, f2);
        }
    }

    @Override // android.view.GestureDetector.SimpleOnGestureListener, android.view.GestureDetector.OnGestureListener
    public boolean onSingleTapUp(MotionEvent e) {
        switch (this.a) {
            case 2:
                Intrinsics.checkNotNullParameter(e, "e");
                ((FullScreenOverlayActivity) this.b).finish();
                return true;
            default:
                return super.onSingleTapUp(e);
        }
    }
}
