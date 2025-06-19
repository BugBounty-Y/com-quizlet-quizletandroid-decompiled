package it.sephiroth.android.library.xtooltip;

import android.content.Context;
import android.graphics.Rect;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.widget.FrameLayout;
import android.widget.TextView;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g extends FrameLayout {
    public final /* synthetic */ i a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(i iVar, Context context) {
        super(context);
        this.a = iVar;
        setClipChildren(false);
        setClipToPadding(false);
    }

    @Override // android.view.ViewGroup, android.view.View
    public final boolean dispatchKeyEvent(KeyEvent event) {
        KeyEvent.DispatcherState keyDispatcherState;
        Intrinsics.f(event, "event");
        i iVar = this.a;
        if (!iVar.b || !iVar.d || !iVar.y) {
            return super.dispatchKeyEvent(event);
        }
        if (event.getKeyCode() == 4 && getKeyDispatcherState() != null) {
            if (event.getAction() == 0 && event.getRepeatCount() == 0) {
                KeyEvent.DispatcherState keyDispatcherState2 = getKeyDispatcherState();
                if (keyDispatcherState2 != null) {
                    keyDispatcherState2.startTracking(event, this);
                }
                return true;
            }
            if (event.getAction() != 1 || (keyDispatcherState = getKeyDispatcherState()) == null || !keyDispatcherState.isTracking(event) || event.isCanceled()) {
                return super.dispatchKeyEvent(event);
            }
            timber.log.c.a.m("Back pressed, close the tooltip", new Object[0]);
            iVar.c();
            return true;
        }
        return super.dispatchKeyEvent(event);
    }

    @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
    public final void onLayout(boolean z, int i, int i2, int i3, int i4) {
        super.onLayout(z, i, i2, i3, i4);
        if (z) {
            int[] iArr = {-1, -1};
            getLocationOnScreen(iArr);
            timber.log.c.a.m("globalVisibleRect: " + iArr[0] + ", " + iArr[1], new Object[0]);
            offsetTopAndBottom(-iArr[1]);
        }
    }

    @Override // android.view.View
    public final void onSizeChanged(int i, int i2, int i3, int i4) {
        super.onSizeChanged(i, i2, i3, i4);
    }

    @Override // android.view.View
    public final boolean onTouchEvent(MotionEvent event) {
        Intrinsics.f(event, "event");
        i iVar = this.a;
        if (!iVar.b || !iVar.d || !iVar.y) {
            return false;
        }
        timber.log.a aVar = timber.log.c.a;
        aVar.g("onTouchEvent: " + event, new Object[0]);
        aVar.a("event position: " + event.getX() + ", " + event.getY(), new Object[0]);
        Rect rect = new Rect();
        TextView textView = iVar.E;
        if (textView == null) {
            Intrinsics.m("mTextView");
            throw null;
        }
        textView.getGlobalVisibleRect(rect);
        boolean zContains = rect.contains((int) event.getX(), (int) event.getY());
        a aVar2 = iVar.o;
        if ((aVar2.a & 4) == 4) {
            iVar.c();
        } else {
            aVar2.getClass();
            if (zContains) {
                iVar.c();
            } else if ((iVar.o.a & 4) == 4 && !zContains) {
                iVar.c();
            }
        }
        return (iVar.o.a & 8) == 8;
    }
}
