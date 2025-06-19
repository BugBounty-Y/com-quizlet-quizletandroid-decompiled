package androidx.compose.ui.window;

import android.content.Context;
import android.os.Build;
import android.view.ContextThemeWrapper;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.compose.material3.C0634i2;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3275u6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3347h2;
import com.quizlet.quizletandroid.R;
import java.util.UUID;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class s extends androidx.activity.u {
    public Function0 d;
    public r e;
    public final View f;
    public final q g;
    public final int h;

    /* JADX WARN: Illegal instructions before constructor call */
    public s(Function0 function0, r rVar, View view, androidx.compose.ui.unit.k kVar, androidx.compose.ui.unit.b bVar, UUID uuid) {
        Context context = view.getContext();
        if (Build.VERSION.SDK_INT < 31) {
            rVar.getClass();
        }
        super(new ContextThemeWrapper(context, R.style.DialogWindowTheme), 0);
        this.d = function0;
        this.e = rVar;
        this.f = view;
        float f = 8;
        Window window = getWindow();
        if (window == null) {
            throw new IllegalStateException("Dialog has no window");
        }
        this.h = window.getAttributes().softInputMode & 240;
        window.requestFeature(1);
        window.setBackgroundDrawableResource(android.R.color.transparent);
        this.e.getClass();
        AbstractC3275u6.b(window, true);
        q qVar = new q(getContext(), window);
        qVar.setTag(R.id.compose_view_saveable_id_tag, "Dialog:" + uuid);
        qVar.setClipChildren(false);
        qVar.setElevation(bVar.c0(f));
        qVar.setOutlineProvider(new C0634i2(3));
        this.g = qVar;
        View decorView = window.getDecorView();
        ViewGroup viewGroup = decorView instanceof ViewGroup ? (ViewGroup) decorView : null;
        if (viewGroup != null) {
            c(viewGroup);
        }
        setContentView(qVar);
        p0.n(qVar, p0.f(view));
        p0.o(qVar, p0.g(view));
        AbstractC3347h2.e(qVar, AbstractC3347h2.b(view));
        d(this.d, this.e, kVar);
        androidx.camera.core.impl.utils.e.a(this.c, this, new b(this, 1));
    }

    public static final void c(ViewGroup viewGroup) {
        viewGroup.setClipChildren(false);
        if (viewGroup instanceof q) {
            return;
        }
        int childCount = viewGroup.getChildCount();
        for (int i = 0; i < childCount; i++) {
            View childAt = viewGroup.getChildAt(i);
            ViewGroup viewGroup2 = childAt instanceof ViewGroup ? (ViewGroup) childAt : null;
            if (viewGroup2 != null) {
                c(viewGroup2);
            }
        }
    }

    @Override // android.app.Dialog, android.content.DialogInterface
    public final void cancel() {
    }

    public final void d(Function0 function0, r rVar, androidx.compose.ui.unit.k kVar) {
        Window window;
        Window window2;
        this.d = function0;
        this.e = rVar;
        rVar.getClass();
        boolean zC = l.c(this.f);
        int i = 1;
        int iK = AbstractC0147y.k(1);
        if (iK != 0) {
            if (iK == 1) {
                zC = true;
            } else {
                if (iK != 2) {
                    throw new NoWhenBranchMatchedException();
                }
                zC = false;
            }
        }
        Window window3 = getWindow();
        Intrinsics.d(window3);
        window3.setFlags(zC ? 8192 : -8193, 8192);
        int iOrdinal = kVar.ordinal();
        if (iOrdinal == 0) {
            i = 0;
        } else if (iOrdinal != 1) {
            throw new NoWhenBranchMatchedException();
        }
        q qVar = this.g;
        qVar.setLayoutDirection(i);
        boolean z = rVar.c;
        if (z && !qVar.c && (window2 = getWindow()) != null) {
            window2.setLayout(-2, -2);
        }
        qVar.c = z;
        if (Build.VERSION.SDK_INT >= 31 || (window = getWindow()) == null) {
            return;
        }
        window.setSoftInputMode(this.h);
    }

    @Override // android.app.Dialog
    public final boolean onTouchEvent(MotionEvent motionEvent) {
        boolean zOnTouchEvent = super.onTouchEvent(motionEvent);
        if (zOnTouchEvent && this.e.b) {
            this.d.invoke();
        }
        return zOnTouchEvent;
    }
}
