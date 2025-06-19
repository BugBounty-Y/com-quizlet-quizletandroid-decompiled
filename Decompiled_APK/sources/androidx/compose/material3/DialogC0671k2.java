package androidx.compose.material3;

import android.content.Context;
import android.os.Build;
import android.view.ContextThemeWrapper;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import androidx.compose.animation.core.C0238e;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3275u6;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3291w6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3347h2;
import com.quizlet.quizletandroid.R;
import java.util.UUID;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.compose.material3.k2, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class DialogC0671k2 extends androidx.activity.u {
    public Function0 d;
    public B2 e;
    public final View f;
    public final C0628h2 g;

    public DialogC0671k2(Function0 function0, B2 b2, View view, androidx.compose.ui.unit.k kVar, androidx.compose.ui.unit.b bVar, UUID uuid, C0238e c0238e, kotlinx.coroutines.C c, boolean z) {
        super(new ContextThemeWrapper(view.getContext(), R.style.EdgeToEdgeFloatingDialogWindowTheme), 0);
        this.d = function0;
        this.e = b2;
        this.f = view;
        float f = 8;
        Window window = getWindow();
        if (window == null) {
            throw new IllegalStateException("Dialog has no window");
        }
        window.requestFeature(1);
        window.setBackgroundDrawableResource(android.R.color.transparent);
        AbstractC3275u6.b(window, false);
        Context context = getContext();
        this.e.getClass();
        C0628h2 c0628h2 = new C0628h2(context, this.d, c0238e, c);
        c0628h2.setTag(R.id.compose_view_saveable_id_tag, "Dialog:" + uuid);
        c0628h2.setClipChildren(false);
        c0628h2.setElevation(bVar.c0(f));
        c0628h2.setOutlineProvider(new C0634i2(0));
        this.g = c0628h2;
        setContentView(c0628h2);
        androidx.lifecycle.p0.n(c0628h2, androidx.lifecycle.p0.f(view));
        androidx.lifecycle.p0.o(c0628h2, androidx.lifecycle.p0.g(view));
        AbstractC3347h2.e(c0628h2, AbstractC3347h2.b(view));
        c(this.d, this.e, kVar);
        com.quizlet.data.repository.school.membership.a aVar = new com.quizlet.data.repository.school.membership.a(window.getDecorView());
        int i = Build.VERSION.SDK_INT;
        AbstractC3291w6 g0 = i >= 35 ? new androidx.core.view.G0(window, aVar) : i >= 30 ? new androidx.core.view.F0(window, aVar) : new androidx.core.view.E0(window, aVar);
        boolean z2 = !z;
        g0.d(z2);
        g0.c(z2);
        androidx.camera.core.impl.utils.e.a(this.c, this, new C0665j2(this, 0));
    }

    public final void c(Function0 function0, B2 b2, androidx.compose.ui.unit.k kVar) {
        this.d = function0;
        this.e = b2;
        b2.getClass();
        ViewGroup.LayoutParams layoutParams = this.f.getRootView().getLayoutParams();
        WindowManager.LayoutParams layoutParams2 = layoutParams instanceof WindowManager.LayoutParams ? (WindowManager.LayoutParams) layoutParams : null;
        int i = 0;
        boolean z = (layoutParams2 == null || (layoutParams2.flags & 8192) == 0) ? false : true;
        Window window = getWindow();
        Intrinsics.d(window);
        window.setFlags(z ? 8192 : -8193, 8192);
        int iOrdinal = kVar.ordinal();
        if (iOrdinal != 0) {
            if (iOrdinal != 1) {
                throw new NoWhenBranchMatchedException();
            }
            i = 1;
        }
        this.g.setLayoutDirection(i);
        Window window2 = getWindow();
        if (window2 != null) {
            window2.setLayout(-1, -1);
        }
        Window window3 = getWindow();
        if (window3 != null) {
            window3.setSoftInputMode(Build.VERSION.SDK_INT >= 30 ? 48 : 16);
        }
    }

    @Override // android.app.Dialog, android.content.DialogInterface
    public final void cancel() {
    }

    @Override // android.app.Dialog
    public final boolean onTouchEvent(MotionEvent motionEvent) {
        boolean zOnTouchEvent = super.onTouchEvent(motionEvent);
        if (zOnTouchEvent) {
            this.d.invoke();
        }
        return zOnTouchEvent;
    }
}
