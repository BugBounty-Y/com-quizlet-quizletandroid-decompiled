package androidx.compose.ui.platform;

import android.graphics.Rect;
import android.os.Handler;
import android.os.Looper;
import android.view.FocusFinder;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.ui.platform.l, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0952l extends kotlin.jvm.internal.r implements Function1 {
    public final /* synthetic */ int a;
    public final /* synthetic */ C0971v b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C0952l(C0971v c0971v, int i) {
        super(1);
        this.a = i;
        this.b = c0971v;
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        androidx.compose.ui.focus.c cVar;
        switch (this.a) {
            case 0:
                int i = ((androidx.compose.ui.input.a) obj).a;
                C0971v c0971v = this.b;
                boolean zRequestFocusFromTouch = true;
                if (i == 1) {
                    zRequestFocusFromTouch = c0971v.isInTouchMode();
                } else if (i != 2) {
                    zRequestFocusFromTouch = false;
                } else if (c0971v.isInTouchMode()) {
                    zRequestFocusFromTouch = c0971v.requestFocusFromTouch();
                }
                return Boolean.valueOf(zRequestFocusFromTouch);
            case 1:
                KeyEvent keyEvent = ((androidx.compose.ui.input.key.b) obj).a;
                C0971v c0971v2 = this.b;
                c0971v2.getClass();
                long jB = androidx.compose.ui.input.key.c.b(keyEvent);
                if (androidx.compose.ui.input.key.a.a(jB, androidx.compose.ui.input.key.a.h)) {
                    cVar = new androidx.compose.ui.focus.c(keyEvent.isShiftPressed() ? 2 : 1);
                } else if (androidx.compose.ui.input.key.a.a(jB, androidx.compose.ui.input.key.a.f)) {
                    cVar = new androidx.compose.ui.focus.c(4);
                } else if (androidx.compose.ui.input.key.a.a(jB, androidx.compose.ui.input.key.a.e)) {
                    cVar = new androidx.compose.ui.focus.c(3);
                } else {
                    cVar = androidx.compose.ui.input.key.a.a(jB, androidx.compose.ui.input.key.a.c) ? true : androidx.compose.ui.input.key.a.a(jB, androidx.compose.ui.input.key.a.l) ? new androidx.compose.ui.focus.c(5) : androidx.compose.ui.input.key.a.a(jB, androidx.compose.ui.input.key.a.d) ? true : androidx.compose.ui.input.key.a.a(jB, androidx.compose.ui.input.key.a.m) ? new androidx.compose.ui.focus.c(6) : androidx.compose.ui.input.key.a.a(jB, androidx.compose.ui.input.key.a.g) ? true : androidx.compose.ui.input.key.a.a(jB, androidx.compose.ui.input.key.a.i) ? true : androidx.compose.ui.input.key.a.a(jB, androidx.compose.ui.input.key.a.n) ? new androidx.compose.ui.focus.c(7) : androidx.compose.ui.input.key.a.a(jB, androidx.compose.ui.input.key.a.b) ? true : androidx.compose.ui.input.key.a.a(jB, androidx.compose.ui.input.key.a.j) ? new androidx.compose.ui.focus.c(8) : null;
                }
                if (cVar != null) {
                    if (androidx.compose.ui.input.key.c.c(keyEvent) == 2) {
                        androidx.compose.ui.geometry.c cVarU = c0971v2.u();
                        androidx.compose.ui.focus.h focusOwner = c0971v2.getFocusOwner();
                        C0962q c0962q = new C0962q(cVar, 1);
                        int i2 = cVar.a;
                        Boolean boolD = ((androidx.compose.ui.focus.j) focusOwner).d(i2, cVarU, c0962q);
                        if (boolD != null ? boolD.booleanValue() : true) {
                            return Boolean.TRUE;
                        }
                        if (!(i2 == 1 || i2 == 2)) {
                            return Boolean.FALSE;
                        }
                        Integer numM = androidx.compose.ui.focus.a.M(i2);
                        if (numM == null) {
                            throw new IllegalStateException("Invalid focus direction");
                        }
                        int iIntValue = numM.intValue();
                        Rect rectW = cVarU != null ? androidx.compose.ui.graphics.F.w(cVarU) : null;
                        if (rectW == null) {
                            throw new IllegalStateException("Invalid rect");
                        }
                        View viewFindNextFocus = c0971v2;
                        while (true) {
                            if (viewFindNextFocus != null) {
                                FocusFinder focusFinder = FocusFinder.getInstance();
                                View rootView = c0971v2.getRootView();
                                Intrinsics.e(rootView, "null cannot be cast to non-null type android.view.ViewGroup");
                                viewFindNextFocus = focusFinder.findNextFocus((ViewGroup) rootView, viewFindNextFocus, iIntValue);
                                if (viewFindNextFocus != null) {
                                    if (!viewFindNextFocus.equals(c0971v2)) {
                                        for (ViewParent parent = viewFindNextFocus.getParent(); parent != null; parent = parent.getParent()) {
                                            if (parent == c0971v2) {
                                                break;
                                            }
                                        }
                                    }
                                }
                            } else {
                                viewFindNextFocus = null;
                            }
                        }
                        if (Intrinsics.b(viewFindNextFocus, c0971v2)) {
                            viewFindNextFocus = null;
                        }
                        if ((viewFindNextFocus == null || !androidx.compose.ui.focus.a.H(viewFindNextFocus, Integer.valueOf(iIntValue), rectW)) && ((androidx.compose.ui.focus.j) c0971v2.getFocusOwner()).b(i2, false, false)) {
                            Boolean boolD2 = ((androidx.compose.ui.focus.j) c0971v2.getFocusOwner()).d(i2, null, new C0962q(cVar, 0));
                            return Boolean.valueOf(boolD2 != null ? boolD2.booleanValue() : true);
                        }
                        return Boolean.TRUE;
                    }
                }
                return Boolean.FALSE;
            case 2:
                Function0 function0 = (Function0) obj;
                C0971v c0971v3 = this.b;
                Handler handler = c0971v3.getHandler();
                if ((handler != null ? handler.getLooper() : null) == Looper.myLooper()) {
                    function0.invoke();
                } else {
                    Handler handler2 = c0971v3.getHandler();
                    if (handler2 != null) {
                        handler2.post(new RunnableC0967t(0, function0));
                    }
                }
                return Unit.a;
            default:
                C0971v c0971v4 = this.b;
                return new V(c0971v4, c0971v4.getTextInputService(), (kotlinx.coroutines.C) obj);
        }
    }
}
